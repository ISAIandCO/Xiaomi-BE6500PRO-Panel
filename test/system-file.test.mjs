import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {inspectSystemFile,MAX_FIRMWARE_BYTES,MAX_BACKUP_BYTES} from '../system-file.mjs';

const rawCrc=bytes=>{let crc=0xffffffff;for(const byte of bytes){crc^=byte;for(let i=0;i<8;i++)crc=crc&1?(crc>>>1)^0xedb88320:crc>>>1;}return crc>>>0;};
const seal=image=>{image.writeUInt32LE(rawCrc(image.subarray(12)),8);return image;};
function firmware(){
  const payloads=[['xiaoqiang_version',Buffer.from("config core 'version'\n option ROM '1.1.123'\n option HARDWARE 'RD08'\n option CHANNEL 'release'\n")],['root.ubi',Buffer.alloc(32,0x12)]];
  const signatureOffset=144+payloads.reduce((n,[,body])=>n+48+body.length,0),image=Buffer.alloc(signatureOffset+272);
  image.write('HDR1');image.writeUInt32LE(signatureOffset,4);image.writeUInt16LE(81,14);image.writeUInt32LE(256,signatureOffset);
  let start=144;
  payloads.forEach(([name,body],i)=>{image.writeUInt32LE(start,16+i*4);image.writeUInt16LE(0xbabe,start);image.writeUInt32LE(body.length,start+8);image.writeInt16LE(-1,start+12);image.write(name,start+16);body.copy(image,start+48);start+=48+body.length;});
  return seal(image);
}
function tar(entries=[{name:'cfg_backup.des',body:'["mi_basic_info","mi_wifi_info","mi_lan_info"]'},{name:'cfg_backup.mbu',body:'synthetic encrypted placeholder'}]){
  const chunks=[];
  for(const {name,body,type='0',prefix='',link=''} of entries){
    const data=Buffer.from(body),head=Buffer.alloc(512);
    head.write(name);head.write('0000600\0',100);head.write('0000000\0',108);head.write('0000000\0',116);head.write(data.length.toString(8).padStart(11,'0')+'\0',124);head.write('00000000000\0',136);head.fill(32,148,156);head.write(type,156);head.write(link,157);head.write('ustar\0',257);head.write('00',263);head.write(prefix,345);
    let checksum=0;for(const byte of head)checksum+=byte;
    head.write(checksum.toString(8).padStart(6,'0')+'\0 ',148);
    chunks.push(head,data,Buffer.alloc((512-data.length%512)%512));
  }
  return Buffer.concat([...chunks,Buffer.alloc(1024)]);
}
const backup=entries=>gzipSync(tar(entries));
const invalid=(bytes,kind,pattern)=>{const answer=inspectSystemFile(bytes,kind);assert.equal(answer.valid,false);assert(answer.errors.some(error=>pattern.test(error)),JSON.stringify(answer.errors));return answer;};

test('Firmware metadata never promotes an unsigned synthetic image to valid',()=>{
  const answer=inspectSystemFile(firmware(),'firmware');
  assert.equal(answer.format,'HDR1');assert.equal(answer.model,'RD08');assert.equal(answer.hardwareId,81);assert.equal(answer.version,'1.1.123');assert.equal(answer.signatureAlgorithm,'RSA-SHA256');
  assert(answer.crcValid);assert(answer.modelMatches);assert.equal(answer.signatureValid,false);assert.equal(answer.valid,false);assert.equal(answer.sha256.length,64);
  assert.deepEqual(answer.sections.map(section=>section.name),['xiaoqiang_version','root.ubi']);
  assert(answer.errors.some(error=>error.includes('public.pem')));
});

test('Firmware rejects invalid bounds, CRC, section overlap, table holes and a different model',()=>{
  let image=firmware();image.writeUInt32LE(0xffffffff,4);invalid(image,'firmware',/смещения/);
  image=firmware();image.writeUInt32LE(128,image.readUInt32LE(4));invalid(image,'firmware',/размер подписи/);
  image=firmware();image[8]^=1;assert.equal(invalid(image,'firmware',/сумма HDR1/).crcValid,false);
  image=firmware();image.writeUInt32LE(144,20);invalid(seal(image),'firmware',/перекрываются/);
  image=firmware();image.writeUInt32LE(0,20);image.writeUInt32LE(144,24);invalid(seal(image),'firmware',/таблица секций/);
  image=firmware();image.writeUInt16LE(80,14);assert.equal(invalid(seal(image),'firmware',/другой модели/).modelMatches,false);
  image=firmware();image.write('../root',144+16);invalid(seal(image),'firmware',/Небезопасное имя/);
  image=firmware();image.writeUInt32LE(0xffffffff,144+8);invalid(seal(image),'firmware',/размер секции/);
  image=firmware();image[0]|=0x80;invalid(image,'firmware',/HDR1/);
  image=firmware();image.write('RN02',image.indexOf(Buffer.from('RD08')));assert.equal(invalid(seal(image),'firmware',/другой модели/).modelMatches,false);
  assert.equal(inspectSystemFile(firmware(),'firmware',{hardware:'RN02'}).modelMatches,false);
});

test('Backup returns allowlisted section labels without returning backup contents',()=>{
  const bytes=backup(),answer=inspectSystemFile(bytes,'restore');
  assert(answer.valid);assert.deepEqual(answer.errors,[]);assert.equal(answer.format,'tar.gz');assert.equal(answer.sha256.length,64);assert.equal(answer.bytes,bytes.length);
  assert.deepEqual(answer.sections.map(section=>section.key),['mi_basic_info','mi_wifi_info','mi_lan_info']);assert.equal(answer.archiveFiles.length,2);assert(answer.expandedBytes<=MAX_BACKUP_BYTES);
  assert.equal(answer.encrypted,true);assert.equal(answer.deviceCompatibilityVerified,false);assert(answer.nativeValidationRequired);
  assert(!JSON.stringify(answer).includes('synthetic encrypted placeholder'));assert(inspectSystemFile(bytes,'backup').valid);
});

test('Backup rejects traversal, links, duplicate names, extra files and missing files',()=>{
  for(const change of [{name:'../cfg_backup.des'},{prefix:'../'},{type:'2',link:'/etc/passwd'},{type:'1',link:'cfg_backup.mbu'},{type:'5'}]){
    invalid(backup([{name:'cfg_backup.des',body:'["mi_wifi_info"]',...change},{name:'cfg_backup.mbu',body:'fixture'}]),'restore',/небезопасный путь|лишний файл/);
  }
  invalid(backup([{name:'cfg_backup.des',body:'[]'},{name:'cfg_backup.des',body:'[]'}]),'restore',/повтор имени/);
  invalid(backup([{name:'cfg_backup.des',body:'[]'},{name:'cfg_backup.mbu',body:'fixture'},{name:'extra',body:'x'}]),'restore',/только cfg_backup/);
  invalid(backup([{name:'cfg_backup.des',body:'["mi_wifi_info"]'}]),'restore',/ровно cfg_backup/);
});

test('Backup rejects corrupt TAR, unsafe descriptions, truncation and decompression bombs',()=>{
  let archive=tar();archive[100]^=1;invalid(gzipSync(archive),'restore',/сумма заголовка/);
  archive=tar();archive[archive.length-1]=1;invalid(gzipSync(archive),'restore',/завершение/);
  archive=tar();archive.write('other',257);invalid(gzipSync(archive),'restore',/формат заголовка/);
  invalid(gzipSync(tar().subarray(0,1500)),'restore',/длина/);
  for(const body of ['{}','[]','["arbitrary"]','["mi_wifi_info","mi_wifi_info"]','["mi_wifi_info",{}]','not json'])invalid(backup([{name:'cfg_backup.des',body},{name:'cfg_backup.mbu',body:'fixture'}]),'restore',/Описание/);
  invalid(gzipSync(Buffer.alloc(MAX_BACKUP_BYTES+1)),'restore',/лимит распаковки/);
  invalid(Buffer.from('not gzip'),'restore',/TAR.GZ/);
});

test('File type and upload limits fail closed without throwing',()=>{
  invalid(Buffer.alloc(MAX_BACKUP_BYTES+1),'restore',/8 МиБ/);
  invalid(Buffer.alloc(MAX_FIRMWARE_BYTES+1),'firmware',/100 МиБ/);
  invalid(Buffer.alloc(0),'firmware',/1 байта/);
  invalid(new Uint8Array([1,2,3]),'restore',/1 байта/);
  invalid(Buffer.from('HDR1'),'firmware',/обрезан/);
  invalid(Buffer.from('x'),'other',/тип системного/);
});
