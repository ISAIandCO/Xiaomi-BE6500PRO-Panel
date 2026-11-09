import {createHash,verify} from 'node:crypto';
import {gunzipSync} from 'node:zlib';

// Native infile nginx limit is 100 MiB, including multipart headers.
export const MAX_FIRMWARE_BYTES=100*1024*1024-4096;
export const MAX_BACKUP_BYTES=8*1024*1024;

// Public firmware trust anchor from the supplied official RD08 1.1.123 image.
const FIRMWARE_PUBLIC_KEY=`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuhCogvvVhAng3ZRJP8Cz
gxIkXvdbz5NHyOpOmYjrass6WL93EHKfS+Qa/NaG4d3u9H2GkgrUbOjjID9mRkiR
voXprgNIEEcWzdHsVOlrwk9K+psXFW9mM+0zKxdgt8cuPnM/UAm9i5XTfDgQNwy8
0Ygcs9qqofm2f3DsK3bR6JyFuf1LbyHUYAymOm2+E7XguPuxUn9i7h1s5/nkWZOm
22kMqYPBZrHf1T5hfZ7XhQGMORaK34a6nk5Vx1qrNrZvZuJdYXldSnvFWO+SHK1Q
J+NE4RD5S6Bs79nB7vTDzLgqCqvtWLgew+s0JE0jLZZpxAwJXO3XYaLV0irO6a6/
YwIDAQAB
-----END PUBLIC KEY-----`;
const LABELS={
  mi_basic_info:'Имя роутера и пароль управления',mi_wifi_info:'Сети и пароли Wi-Fi',
  mi_network_info:'Подключение к Интернету',mi_lan_info:'Локальная сеть и DHCP',
  mi_arn_info:'Контроль доступа',mi_access_info:'Доступ к управлению',
  mi_mobile_info:'Мобильная сеть',mi_sms_info:'Сообщения SMS'
};
const table=Uint32Array.from({length:256},(_,n)=>{for(let bit=0;bit<8;bit++)n=n&1?0xedb88320^(n>>>1):n>>>1;return n>>>0;});
const rawCrc=bytes=>{let n=0xffffffff;for(const byte of bytes)n=table[(n^byte)&255]^(n>>>8);return n>>>0;};
const fail=message=>{throw new Error(message);};
const bounds=(bytes,offset,length)=>{if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<0||offset>bytes.length-length)fail('Файл обрезан или содержит неверные смещения.');};
const zero=bytes=>bytes.every(byte=>byte===0);
const text=bytes=>{try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('Текстовые метаданные не являются UTF-8.');}};
function cstring(bytes){
  const end=bytes.indexOf(0);
  if(end<0||!zero(bytes.subarray(end)))fail('Некорректное имя файла в заголовке.');
  return text(bytes.subarray(0,end));
}

function firmware(bytes,result,hardware){
  bounds(bytes,0,144);
  if(!bytes.subarray(0,4).equals(Buffer.from('HDR1')))fail('Ожидается штатный образ прошивки HDR1.');
  result.format='HDR1';
  const signatureOffset=bytes.readUInt32LE(4);
  if(signatureOffset<192)fail('Неверное смещение подписи прошивки.');
  bounds(bytes,signatureOffset,16);
  const signatureBytes=bytes.readUInt32LE(signatureOffset);
  if(signatureBytes!==256||signatureOffset+16+signatureBytes!==bytes.length)fail('Неверный размер подписи прошивки.');
  result.hardwareId=bytes.readUInt16LE(14);
  result.crcValid=rawCrc(bytes.subarray(12))===bytes.readUInt32LE(8);
  // mkxqimage reads 0x90 bytes (32 offsets) and verifies firmware with SHA256.
  result.signatureAlgorithm='RSA-SHA256';
  result.signatureValid=verify('RSA-SHA256',bytes.subarray(12,signatureOffset),FIRMWARE_PUBLIC_KEY,bytes.subarray(signatureOffset+16));
  if(!result.crcValid)result.errors.push('Контрольная сумма HDR1 не совпадает.');
  if(!result.signatureValid)result.errors.push('Подпись прошивки не подтверждена встроенным ключом Xiaomi public.pem.');
  const sections=[];let ended=false;
  for(let p=16;p<144;p+=4){
    const start=bytes.readUInt32LE(p);
    if(!start){ended=true;continue;}
    if(ended||start<144||start>signatureOffset-48)fail('Некорректная таблица секций HDR1.');
    bounds(bytes,start,48);
    const size=bytes.readUInt32LE(start+8),name=cstring(bytes.subarray(start+16,start+48));
    if(bytes.readUInt16LE(start)!==0xbabe||!size||size>signatureOffset-start-48)fail('Неверный заголовок или размер секции прошивки.');
    if(!/^[A-Za-z0-9_.-]+$/.test(name)||name==='.'||name==='..')fail('Небезопасное имя секции прошивки.');
    sections.push({name,bytes:size,offset:start+48,mtd:bytes.readInt16LE(start+12),start});
  }
  if(!sections.length)fail('В прошивке отсутствуют секции.');
  const sorted=[...sections].sort((a,b)=>a.start-b.start);
  for(let i=1;i<sorted.length;i++)if(sorted[i].start<sorted[i-1].offset+sorted[i-1].bytes)fail('Секции прошивки перекрываются.');
  result.sections=sections.map(({start,...section})=>section);
  const versions=sections.filter(section=>section.name==='xiaoqiang_version');
  if(versions.length!==1||versions[0].bytes>65536||!sections.some(section=>section.name==='root.ubi'))fail('Нет однозначного описания версии или корневой системы RD08.');
  const version=versions[0],description=text(bytes.subarray(version.offset,version.offset+version.bytes)).replace(/\0+$/,'');
  if(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(description))fail('Описание версии содержит управляющие символы.');
  const metadata={};
  for(const match of description.matchAll(/^\s*option\s+(ROM|HARDWARE|CHANNEL)\s+(['"])([^'"\r\n]*)\2\s*$/gm)){
    if(Object.hasOwn(metadata,match[1]))fail('Описание версии содержит повтор метаданных.');
    metadata[match[1]]=match[3];
  }
  if(!/^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(metadata.ROM||'')||!/^[A-Z0-9]{2,16}$/.test(metadata.HARDWARE||''))fail('Некорректная версия или модель в описании прошивки RD08.');
  result.model=metadata.HARDWARE;result.version=metadata.ROM;
  if(metadata.CHANNEL)result.channel=metadata.CHANNEL;
  result.modelMatches=hardware==='RD08'&&result.model===hardware&&result.hardwareId===81;
  if(!result.modelMatches)result.errors.push('Образ предназначен для другой модели роутера.');
  result.nativeValidationRequired=true;
}

function octal(bytes){
  if(bytes.some(byte=>byte>127))fail('Некорректное числовое поле TAR.');
  const field=bytes.toString('ascii').replace(/[\0 ]+$/,'').replace(/^ +/,'');
  if(!/^[0-7]+$/.test(field))fail('Некорректное числовое поле TAR.');
  const number=parseInt(field,8);
  if(!Number.isSafeInteger(number))fail('Слишком большое числовое поле TAR.');
  return number;
}

function backup(bytes,result){
  if(bytes[0]!==0x1f||bytes[1]!==0x8b||bytes[2]!==8)fail('Ожидается штатная резервная копия TAR.GZ.');
  result.format='tar.gz';
  let archive;
  try{archive=gunzipSync(bytes,{maxOutputLength:MAX_BACKUP_BYTES});}catch{fail('Архив повреждён или превышает лимит распаковки 8 МиБ.');}
  if(archive.length<2048||archive.length%512)fail('Некорректная длина архива TAR.');
  const files=new Map();let p=0,terminated=false;
  while(p<archive.length){
    bounds(archive,p,512);
    const header=archive.subarray(p,p+512);
    if(zero(header)){
      if(p+1024>archive.length||!zero(archive.subarray(p)))fail('Некорректное завершение архива TAR.');
      terminated=true;break;
    }
    if(files.size>=2)fail('Резервная копия должна содержать только cfg_backup.des и cfg_backup.mbu.');
    const marker=header.subarray(257,265);
    if(!zero(marker)&&!marker.equals(Buffer.from('ustar\0'+'00'))&&!marker.equals(Buffer.from('ustar '+' \0')))fail('Неизвестный формат заголовка TAR.');
    const name=cstring(header.subarray(0,100));
    if(!['cfg_backup.des','cfg_backup.mbu'].includes(name)||files.has(name)||!zero(header.subarray(345,500))||header[156]!==0&&header[156]!==48||!zero(header.subarray(157,257)))fail('TAR содержит лишний файл, небезопасный путь, ссылку или повтор имени.');
    let checksum=0;for(let i=0;i<512;i++)checksum+=i>=148&&i<156?32:header[i];
    if(octal(header.subarray(148,156))!==checksum)fail('Контрольная сумма заголовка TAR не совпадает.');
    const size=octal(header.subarray(124,136)),start=p+512,end=start+size,next=start+Math.ceil(size/512)*512;
    if(!size||size>MAX_BACKUP_BYTES||next>archive.length)fail('Неверный размер файла резервной копии.');
    if(!zero(archive.subarray(end,next)))fail('Некорректное заполнение блока TAR.');
    files.set(name,{size,start});p=next;
  }
  if(!terminated||files.size!==2||!files.has('cfg_backup.des')||!files.has('cfg_backup.mbu'))fail('В резервной копии нужны ровно cfg_backup.des и cfg_backup.mbu.');
  const des=files.get('cfg_backup.des');
  if(des.size>16384)fail('Описание резервной копии превышает 16 КиБ.');
  let keys;
  try{keys=JSON.parse(text(archive.subarray(des.start,des.start+des.size)));}catch{fail('Описание резервной копии не является корректным JSON.');}
  if(!Array.isArray(keys)||!keys.length||keys.length>Object.keys(LABELS).length||keys.some(key=>typeof key!=='string'||!Object.hasOwn(LABELS,key))||new Set(keys).size!==keys.length)fail('Описание резервной копии содержит неизвестные или повторяющиеся разделы.');
  result.sections=keys.map(key=>({key,label:LABELS[key]}));
  result.archiveFiles=[...files].map(([name,file])=>({name,bytes:file.size}));
  result.expandedBytes=archive.length;result.encrypted=true;
  result.deviceCompatibilityVerified=false;result.nativeValidationRequired=true;
}

export function inspectSystemFile(bytes,kind,{hardware='RD08'}={}){
  const result={kind,format:null,bytes:Buffer.isBuffer(bytes)?bytes.length:0,sha256:null,valid:false,errors:[]};
  try{
    if(!['firmware','restore','backup'].includes(kind))fail('Неизвестный тип системного файла.');
    const limit=kind==='firmware'?MAX_FIRMWARE_BYTES:MAX_BACKUP_BYTES;
    if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>limit)fail(`Выберите файл размером от 1 байта до ${Math.ceil(limit/1024/1024)} МиБ${kind==='firmware'?' с резервом 4 КиБ для формы':''}.`);
    result.sha256=createHash('sha256').update(bytes).digest('hex');
    if(kind==='firmware')firmware(bytes,result,String(hardware).toUpperCase());else backup(bytes,result);
    result.valid=result.errors.length===0;
  }catch(error){result.errors.push(error.message||'Не удалось проверить файл.');}
  return result;
}
