import test from 'node:test';
import assert from 'node:assert/strict';
import {deflateRawSync} from 'node:zlib';
import {inspectPluginPackage,MAX_PLUGIN_BYTES} from '../plugin-package.mjs';

const crc=bytes=>{let n=0xffffffff;for(const b of bytes){n^=b;for(let k=0;k<8;k++)n=n&1?(n>>>1)^0xedb88320:n>>>1;}return (n^0xffffffff)>>>0;};
const manifest='plugin_id="123456789";\nname="Fixture";\nversion="1.0.0";\nsupported_rom="miwifi_rom_2";\nsdk_level="5";\n';
function zip(entries=[{name:'manifest',content:manifest}],method=8){
  const local=[],central=[];let offset=0;
  for(const entry of entries){
    const name=Buffer.from(entry.name),body=Buffer.from(entry.content),packed=method===8?deflateRawSync(body):body,checksum=crc(body);
    const l=Buffer.alloc(30),c=Buffer.alloc(46);l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(0x800,6);l.writeUInt16LE(method,8);l.writeUInt32LE(checksum,14);l.writeUInt32LE(packed.length,18);l.writeUInt32LE(body.length,22);l.writeUInt16LE(name.length,26);
    c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0x800,8);c.writeUInt16LE(method,10);c.writeUInt32LE(checksum,16);c.writeUInt32LE(packed.length,20);c.writeUInt32LE(body.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(entry.mode??0x81ed0000,38);c.writeUInt32LE(offset,42);
    local.push(l,name,packed);central.push(c,name);offset+=l.length+name.length+packed.length;
  }
  const dir=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(dir.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...local,dir,end]);
}
function mipk(payload=zip()){
  const head=Buffer.alloc(20),cert=Buffer.alloc(4),sig=Buffer.alloc(260);head.write('MIPK');head.writeUInt32LE(1,12);head.writeUInt32LE(payload.length,16);sig.writeUInt32LE(256);
  const result=Buffer.concat([head,payload,cert,sig]);result.writeUInt32LE(crc(result.subarray(8)),4);return result;
}
function wrapper(inner=mipk(),model='RD08'){
  const signatureOffset=152+inner.length,result=Buffer.alloc(signatureOffset+144);result.write('HDR1');result.writeUInt32LE(signatureOffset,4);result.writeUInt32LE(104,16);
  [1,1,0,1,1,1000].forEach((n,i)=>result.writeUInt32LE(n,48+i*4));result.write(model,72);result.writeUInt16LE(0xbabe,104);result.writeUInt32LE(inner.length,112);result.write('app.mpk',120);inner.copy(result,152);result.writeUInt32LE(128,signatureOffset);result.writeUInt32LE((crc(result.subarray(12))^0xffffffff)>>>0,8);return result;
}

test('Native package inspector reads bounded metadata without treating fake signatures as trusted',()=>{
  assert.equal(crc(Buffer.from('123456789')),0xcbf43926);
  const answer=inspectPluginPackage(wrapper());
  assert.equal(answer.format,'HDR1');assert.equal(answer.model,'RD08');assert(answer.modelMatches);assert(answer.romMatches);assert(answer.crcValid);assert(answer.inner.crcValid);
  assert.equal(answer.inner.manifest.plugin_id,'123456789');assert.equal(answer.inner.manifest.sdk_level,'5');assert.equal(answer.inner.files[0].name,'manifest');
  assert.equal(answer.signatureValid,false);assert.equal(answer.inner.signatureValid,false);assert.equal(answer.uploadable,false);
  assert(answer.problems.some(x=>x.includes('plugin_public.pem')));assert(answer.problems.some(x=>x.includes('MIWIFI CA')));
  assert.equal(answer.sha256.length,64);
});
test('Raw MIPK can be inspected but cannot bypass the required web wrapper',()=>{
  const answer=inspectPluginPackage(mipk(zip(undefined,0)));
  assert.equal(answer.format,'MIPK');assert.equal(answer.uploadable,false);assert(answer.problems.some(x=>x.includes('HDR1')));
  assert.throws(()=>inspectPluginPackage(zip()),/HDR1\/MIPK/);
  const legacy=mipk();legacy.writeUInt32LE(0,12);legacy.writeUInt32LE(crc(legacy.subarray(8)),4);
  assert.throws(()=>inspectPluginPackage(legacy),/старого SDK.*type 0/);
});
test('Native matching follows componentwise version bounds and the exact model',()=>{
  const image=wrapper();
  assert.equal(inspectPluginPackage(image,{firmware:'1.2.0'}).romMatches,false);
  assert.equal(inspectPluginPackage(image,{hardware:'RN02'}).modelMatches,false);
  assert.throws(()=>inspectPluginPackage(image,{firmware:'bad'}),/версии/);
  image[8]^=1;assert.equal(inspectPluginPackage(image).crcValid,false);
});
test('Malformed lengths, unsupported SDK, traversal, links and duplicate ZIP entries are rejected',()=>{
  const bad=wrapper();bad.writeUInt32LE(0xffffffff,4);assert.throws(()=>inspectPluginPackage(bad),/смещения/);
  assert.throws(()=>inspectPluginPackage(Buffer.alloc(MAX_PLUGIN_BYTES+1)),/48 МиБ/);
  assert.throws(()=>inspectPluginPackage(mipk(zip([{name:'../manifest',content:manifest}]))),/небезопасный/);
  assert.throws(()=>inspectPluginPackage(mipk(zip([{name:'a//manifest',content:manifest}]))),/небезопасный/);
  assert.throws(()=>inspectPluginPackage(mipk(zip([{name:'manifest',content:manifest,mode:0xa1ff0000}]))),/ссылку/);
  assert.throws(()=>inspectPluginPackage(mipk(zip([{name:'manifest',content:manifest},{name:'manifest',content:manifest}]))),/повтор/);
  const unsupported=inspectPluginPackage(mipk(zip([{name:'manifest',content:manifest.replace('sdk_level="5"','sdk_level="6"')}])));
  assert(unsupported.problems.some(x=>x.includes('SDK')));
  const vendor=inspectPluginPackage(mipk(zip([{name:'manifest',content:manifest.replace('sdk_level="5"','sdk_level="100"')}])));
  assert.equal(vendor.inner.sdkMode,'vendor-special');assert(!vendor.problems.some(x=>x.includes('SDK')));
});
test('Corrupt manifest data and overlapping archive entries do not reach native extraction',()=>{
  const bytes=zip(undefined,0);bytes[30+Buffer.byteLength('manifest')]^=1;
  assert.throws(()=>inspectPluginPackage(mipk(bytes)),/Manifest повреждён/);
  const image=wrapper();image.writeUInt32LE(104,20);
  assert.throws(()=>inspectPluginPackage(image),/ровно одна/);
});
