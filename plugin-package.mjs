import {createHash,verify,X509Certificate} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {PanelError} from './core.mjs';

export const MAX_PLUGIN_BYTES=48*1024*1024;
// Public trust anchors copied from the supplied official RD08 1.1.123 image.
const PLUGIN_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrmdHMYLobbDZE9uQ29BiC6z62\niNG6hxHJxRtZ/fk6AN4Idf21vqtPWUEgyTMmE3tdUouvPZHngMz3iGIoJVC55bha\nqm2QQiJVkn68OjzlTpm4xdJn0JZyF1d0VfA6gh3qdmAForSm03Cyy1pkxc7cSkGZ\nETilLpFCQL7IUB4kawIDAQAB\n-----END PUBLIC KEY-----\n";
const MIWIFI_CA="-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIJAPleDI5k28Y/MA0GCSqGSIb3DQEBBQUAMIGVMQswCQYD\nVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzETMBEG\nA1UECgwKWGlhb21pLmNvbTEaMBgGA1UECwwRaHR0cDovL21pd2lmaS5jb20xDzAN\nBgNVBAMMBk1JV0lGSTEgMB4GCSqGSIb3DQEJARYRbWl3aWZpQHhpYW9taS5jb20w\nHhcNMTQwMzI4MDgwMTQ3WhcNMjQwMzI1MDgwMTQ3WjCBlTELMAkGA1UEBhMCQ04x\nEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWppbmcxEzARBgNVBAoMClhp\nYW9taS5jb20xGjAYBgNVBAsMEWh0dHA6Ly9taXdpZmkuY29tMQ8wDQYDVQQDDAZN\nSVdJRkkxIDAeBgkqhkiG9w0BCQEWEW1pd2lmaUB4aWFvbWkuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvU8osDiG2jTVMpjeu0i05QYwMl4rBgk6\nueOnCG+ZFSOZrc6FjiDDCsgJ4gF/lArYEr2q29Ug54KtqTJWa7AegIlZqtXm8bLk\nragWT1qZaDvq6tZVUvFGwcRblUBl2cVM/jvJvwgCyv98foqTtKeEzoQV/NvtPY6V\nK3X081w8ixvMrj0PZdDAhO3JK2laMvJbUqKrDQv+12TI8Sqjz+T7ospcAQjxh5Su\nFktvVg8Uowqmv5jEPg5UL7nq0lm9X3AlHq2ITHcQs1zZSYgLu6gstfTjjMV1REhN\nFg0I6XiA3+SOudlcy3R/vTV9HtmRMCA0aw7dKxNhesGj6Rx7h0qUCQIDAQABo1Aw\nTjAdBgNVHQ4EFgQU7ETAILXk90CGGphGbr3Woy9BocYwHwYDVR0jBBgwFoAU7ETA\nILXk90CGGphGbr3Woy9BocYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC\nAQEArYUQf2lSIgd1u8j9u8wJWcZKc2nnHuoRqXVIAKhEaSvuLxbiTY0d1d2oc9wi\nJ0sLsscPZix1tbVtIynSJU3MoaGa4SYZk6K9H8niPy3IkQgIit9aP1Ww0zNLZQwh\nSr/QLFg2jKSqiE2n3+ftp9uLwIMv7WgjFNREddaday0lbPWzxOoSuuBU9XJApfmd\n99n2tyHYKsj7jI6e+jeEFc8ydPnagOwsEUvUP3cjNQmCYEnhD06zHazHPQFPF5iE\nOyouB7tA0cStAr2mMmGgeIROik56dBqb1qfH+h1rr6hqlTiixCyU8xX5AbnU3Uc4\njNAlkBNyV6MhMiwYdvbZuj3pFg==\n-----END CERTIFICATE-----\n";
const CA_PUBLIC_KEY=new X509Certificate(MIWIFI_CA).publicKey;
const table=Uint32Array.from({length:256},(_,n)=>{for(let b=0;b<8;b++)n=n&1?0xedb88320^(n>>>1):n>>>1;return n>>>0;});
const crc=bytes=>{let n=0xffffffff;for(const b of bytes)n=table[(n^b)&255]^(n>>>8);return (n^0xffffffff)>>>0;};
const fail=message=>{throw new PanelError(message);};
const bounds=(bytes,offset,length)=>{if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<0||offset>bytes.length-length)fail('Пакет обрезан или содержит неверные смещения.');};
const u16=(b,p)=>{bounds(b,p,2);return b.readUInt16LE(p);};
const u32=(b,p)=>{bounds(b,p,4);return b.readUInt32LE(p);};
const part=(b,p,n)=>{bounds(b,p,n);return b.subarray(p,p+n);};
const ascii=b=>b.subarray(0,b.indexOf(0)<0?b.length:b.indexOf(0)).toString('ascii');
const validSignature=(bytes,signature,key)=>{try{return verify('RSA-SHA1',bytes,key,signature);}catch{return false;}};

function zipManifest(bytes){
  let end=-1;
  for(let p=bytes.length-22;p>=Math.max(0,bytes.length-65557);p--)if(u32(bytes,p)===0x06054b50&&p+22+u16(bytes,p+20)===bytes.length){end=p;break;}
  if(end<0)fail('Внутри MIPK не найден обычный ZIP-архив.');
  const count=u16(bytes,end+10),directory=u32(bytes,end+16),directorySize=u32(bytes,end+12);
  if(u16(bytes,end+4)||u16(bytes,end+6)||u16(bytes,end+8)!==count||count===65535||count>4096||directory+directorySize!==end)fail('Многотомный ZIP, ZIP64 или слишком большой каталог не поддерживается.');
  const names=new Set(),ranges=[],files=[];let p=directory,total=0,manifest;
  for(let i=0;i<count;i++){
    if(u32(bytes,p)!==0x02014b50)fail('Повреждён каталог ZIP.');
    bounds(bytes,p,46);
    const flags=u16(bytes,p+8),method=u16(bytes,p+10),checksum=u32(bytes,p+16),compressed=u32(bytes,p+20),size=u32(bytes,p+24),nameSize=u16(bytes,p+28),extra=u16(bytes,p+30),comment=u16(bytes,p+32),mode=u32(bytes,p+38)>>>16,local=u32(bytes,p+42);
    const nameBytes=part(bytes,p+46,nameSize);let name;
    try{name=new TextDecoder('utf-8',{fatal:true}).decode(nameBytes);}catch{fail('Имя файла ZIP не является UTF-8.');}
    const segments=name.endsWith('/')?name.slice(0,-1).split('/'):name.split('/');
    if(!name||name.includes('\\')||name.includes('\0')||name.startsWith('/')||name.includes(':')||segments.some(s=>!s||s==='..'||s==='.')||names.has(name)||(mode&0xf000)===0xa000)fail('ZIP содержит небезопасный путь, ссылку или повтор файла.');
    if(flags&1||![0,8].includes(method)||compressed===0xffffffff||size===0xffffffff||size>128*1024*1024||(total+=size)>128*1024*1024)fail('ZIP зашифрован, использует неизвестное сжатие или превышает лимит распаковки 128 МиБ.');
    names.add(name);
    if(u32(bytes,local)!==0x04034b50||u16(bytes,local+6)!==flags||u16(bytes,local+8)!==method)fail('Локальный заголовок ZIP не совпадает с каталогом.');
    const localNameSize=u16(bytes,local+26),localExtra=u16(bytes,local+28),start=local+30+localNameSize+localExtra;
    if(!part(bytes,local+30,localNameSize).equals(nameBytes)||start+compressed>directory)fail('Неверное имя или размер файла ZIP.');
    if(!(flags&8)&&(u32(bytes,local+14)!==checksum||u32(bytes,local+18)!==compressed||u32(bytes,local+22)!==size))fail('Размер или CRC локального файла ZIP не совпадает с каталогом.');
    ranges.push([local,start+compressed]);files.push({name,bytes:size});
    if(name==='manifest'){
      if(size>65536)fail('Manifest превышает 64 КиБ.');
      const packed=part(bytes,start,compressed);let content;
      try{content=method===0?packed:inflateRawSync(packed,{maxOutputLength:65536});}catch{fail('Не удалось прочитать manifest.');}
      if(content.length!==size||crc(content)!==checksum)fail('Manifest повреждён.');
      manifest=content.toString('utf8');
    }
    p+=46+nameSize+extra+comment;
    if(p>directory+directorySize)fail('Каталог ZIP выходит за границы.');
  }
  if(p!==end)fail('Неполный каталог ZIP.');
  ranges.sort((a,b)=>a[0]-b[0]);
  for(let i=1;i<ranges.length;i++)if(ranges[i][0]<ranges[i-1][1])fail('Файлы ZIP перекрываются.');
  if(!manifest)fail('В корне ZIP отсутствует manifest.');
  const fields={};
  for(const key of ['plugin_id','name','version','developer','supported_rom','sdk_level','plugin_class']){
    const match=manifest.match(new RegExp('(?:^|[;\\r\\n])\\s*'+key+'\\s*=\\s*(?:"([^"\\r\\n]*)"|([0-9]+))\\s*(?:;|$)','m'));
    if(match)fields[key]=match[1]??match[2];
  }
  if(!/^[0-9]{1,24}$/.test(fields.plugin_id||'')||!fields.name||!fields.version)fail('Manifest не содержит корректные plugin_id, name и version.');
  return {manifest:fields,files,unpackedBytes:total};
}

function mipk(bytes){
  if(ascii(part(bytes,0,4))!=='MIPK')fail('Секция плагина не является MIPK.');
  const kind=u32(bytes,8),signType=u32(bytes,12),payloadLength=u32(bytes,16);
  if(signType===0)fail('MIPK использует подпись разработчика старого SDK (type 0); исследованный менеджер RD08 требует type 1.');
  if(kind>1||signType!==1)fail('Неизвестная версия или тип подписи MIPK.');
  const payload=part(bytes,20,payloadLength),certificateLength=u32(bytes,20+payloadLength),certificateEnd=24+payloadLength+certificateLength;
  bounds(bytes,24+payloadLength,certificateLength);
  const signatureLength=u32(bytes,certificateEnd),signature=part(bytes,certificateEnd+4,signatureLength);
  if(certificateEnd+4+signatureLength!==bytes.length||signatureLength!==256)fail('Неверный размер подписи MIPK.');
  return {kind,signType,payloadBytes:payloadLength,certificateBytes:certificateLength,crcValid:crc(bytes.subarray(8))===u32(bytes,4),signatureValid:validSignature(bytes.subarray(8,certificateEnd),signature,CA_PUBLIC_KEY),...zipManifest(payload)};
}

export function inspectPluginPackage(bytes,{hardware='RD08',firmware='1.1.123'}={}){
  if(!Buffer.isBuffer(bytes)||bytes.length<28||bytes.length>MAX_PLUGIN_BYTES)fail('Выберите пакет размером от 28 байт до 48 МиБ.');
  const result={format:ascii(part(bytes,0,4)),bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),problems:[],uploadable:false};
  if(result.format==='MIPK'){
    result.inner=mipk(bytes);
    result.problems.push('Это внутренний MIPK. Штатная веб-загрузка RD08 ожидает подписанную оболочку HDR1.');
  }else if(result.format==='HDR1'){
    const signatureOffset=u32(bytes,4),signatureLength=u32(bytes,signatureOffset);
    if(signatureOffset<104||signatureLength!==128)fail('Неверный заголовок подписи HDR1.');
    const signature=part(bytes,signatureOffset+16,signatureLength);
    const min=[0,4,8].map(n=>u32(bytes,48+n)),max=[0,4,8].map(n=>u32(bytes,60+n)),model=ascii(part(bytes,72,32));
    const version=firmware.split('.').map(Number);
    if(version.length!==3||version.some(n=>!Number.isInteger(n)||n<0))fail('Неизвестный формат текущей версии прошивки.');
    result.model=model;result.rom={min:min.join('.'),max:max.join('.')};
    result.crcValid=((crc(bytes.subarray(12))^0xffffffff)>>>0)===u32(bytes,8);
    result.signatureValid=validSignature(bytes.subarray(12,signatureOffset),signature,PLUGIN_PUBLIC_KEY);
    result.modelMatches=model===hardware;
    // mkxqplugin -F compares all three components independently.
    result.romMatches=version.every((n,i)=>n>=min[i]&&n<=max[i]);
    const blocks=[];
    for(let p=16;p<48;p+=4){
      const start=u32(bytes,p);if(!start)break;
      if(start<104||start+48>signatureOffset||u16(bytes,start)!==0xbabe)fail('Неверный заголовок секции HDR1.');
      const length=u32(bytes,start+8),name=ascii(part(bytes,start+16,32));
      if(!name||/[\\/:\x00-\x1f]/.test(name)||name==='.'||name==='..'||start+48+length>signatureOffset)fail('Небезопасное имя или размер секции HDR1.');
      blocks.push({name,bytes:length,start});
    }
    // -F renames extracted blocks to one fixed path; multiple blocks are ambiguous.
    if(blocks.length!==1)fail('Для загрузки плагина требуется ровно одна секция HDR1.');
    result.sections=blocks.map(({name,bytes})=>({name,bytes}));
    result.inner=mipk(part(bytes,blocks[0].start+48,blocks[0].bytes));
    if(!result.crcValid)result.problems.push('Контрольная сумма HDR1 не совпадает.');
    if(!result.signatureValid)result.problems.push('Подпись оболочки не подтверждена ключом Xiaomi plugin_public.pem.');
    if(!result.modelMatches)result.problems.push('Пакет предназначен для другой модели.');
    if(!result.romMatches)result.problems.push('Версия прошивки не входит в диапазон пакета.');
  }else fail('Поддерживается только нативный пакет HDR1/MIPK; ZIP, APK и IPK не подходят.');
  if(!result.inner.crcValid)result.problems.push('Контрольная сумма MIPK не совпадает.');
  if(!result.inner.signatureValid)result.problems.push('Подпись MIPK не подтверждена встроенным ключом MIWIFI CA.');
  if(result.inner.manifest.supported_rom!=='miwifi_rom_2')result.problems.push('Manifest не предназначен для miwifi_rom_2.');
  const sdk=Number(result.inner.manifest.sdk_level);
  // Native manifest validation reserves values above 99 for vendor packages.
  if(!Number.isSafeInteger(sdk)||sdk<1||sdk>2147483647||(sdk>5&&sdk<=99))result.problems.push('Требуется неподдерживаемый или неизвестный уровень SDK.');
  result.inner.sdkMode=sdk>99?'vendor-special':'standard';
  result.uploadable=result.format==='HDR1'&&result.problems.length===0;
  return result;
}
