import dgram from 'node:dgram';
import {createCipheriv,createDecipheriv,createHash,randomInt,timingSafeEqual} from 'node:crypto';
import {isIPv4} from 'node:net';

// Wire format: https://github.com/rytilahti/python-miio/blob/master/miio/protocol.py
// RD08 native forwarding and method evidence: ../research/security-miio-udp-feasibility.txt
const PORT=54321, MAX_PACKET=4096;
const METHODS=Object.freeze({bleState:'miIO.ble_gateway_state',bleVersion:'miIO.bt_gateway_version',bleEnable:'miIO.ble_gateway_enable'});
const md5=data=>createHash('md5').update(data).digest();
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const fail=(code,message)=>Object.assign(new Error(message),{code});
function lanHost(host){
 if(typeof host!=='string'||!isIPv4(host))return false;
 const p=host.split('.').map(Number);
 return p[3]!==0&&p[3]!==255&&(p[0]===10||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168));
}
function deviceNumber(value){
 if(typeof value==='number'&&Number.isSafeInteger(value)&&value>0)value=String(value);
 if(typeof value==='string'&&/^[1-9]\d{0,19}$/.test(value)){const n=BigInt(value);if(n<0xffffffffffffffffn)return n;}
 throw fail('MIIO_CONFIG','Неверный идентификатор MIIO устройства.');
}
function gatewayState(result){
 if(!plain(result)||(result.state!==0&&result.state!==1)||Object.keys(result).some(k=>k!=='state'))throw fail('MIIO_RESULT','Неизвестный ответ состояния Bluetooth шлюза.');
 return {enabled:result.state===1};
}
function gatewayVersion(result){
 const keys=['bt_gateway_version','app_version','app_sdk','build_feature','cm_build_info'];
 if(!plain(result)||Object.keys(result).some(k=>!keys.includes(k))||!['app_version','app_sdk','build_feature','cm_build_info'].every(k=>typeof result[k]==='string'&&result[k].length>0&&result[k].length<=256)||('bt_gateway_version'in result&&(typeof result.bt_gateway_version!=='string'||result.bt_gateway_version.length<1||result.bt_gateway_version.length>256)))throw fail('MIIO_RESULT','Неизвестный ответ версии Bluetooth шлюза.');
 return {version:result.bt_gateway_version||result.app_version};
}

export class MiioLocal{
 #host;#token;#key;#iv;#deviceId;#timeout;#closed=false;#busy=false;#verifiedState=false;#sockets=new Map();#id=randomInt(1,0x7fffffff);
 constructor({host,token,deviceId,timeoutMs=2500}={}){
  if(!lanHost(host)||typeof token!=='string'||!/^([a-f\d]{32})$/i.test(token)||/^(0{32}|f{32})$/i.test(token)||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000)throw fail('MIIO_CONFIG','Нужны локальный IPv4 адрес и 32-значный MIIO токен устройства.');
  this.#host=host;this.#deviceId=deviceId===undefined?null:deviceNumber(deviceId);this.#timeout=timeoutMs;
  this.#token=Buffer.from(token,'hex');this.#key=md5(this.#token);this.#iv=md5(Buffer.concat([this.#key,this.#token]));
 }
 close(){
  if(this.#closed)return;
  this.#closed=true;this.#verifiedState=false;
  for(const finish of [...this.#sockets.values()])finish(fail('MIIO_CLOSED','Сеанс MIIO закрыт.'));
  this.#token.fill(0);this.#key.fill(0);this.#iv.fill(0);
 }
 getState(){return this.request('bleState');}
 getVersion(){return this.request('bleVersion');}
 setEnabled(enable){return this.request('bleEnable',{enable});}
 async request(method,params={}){
  if(!Object.hasOwn(METHODS,method)||!plain(params)||(method==='bleEnable'?(Object.keys(params).length!==1||typeof params.enable!=='boolean'):Object.keys(params).length!==0))throw fail('MIIO_METHOD','Недопустимая команда Bluetooth шлюза.');
  if(this.#closed)throw fail('MIIO_CLOSED','Сеанс MIIO закрыт.');
  if(this.#busy)throw fail('MIIO_BUSY','Предыдущий запрос MIIO ещё выполняется.');
  this.#busy=true;
  try{
   if(method==='bleVersion')return gatewayVersion(await this.#exchange(method,{}));
   if(method==='bleState'){
    const state=gatewayState(await this.#exchange(method,{}));this.#verifiedState=true;return state;
   }
   if(!this.#verifiedState)throw fail('MIIO_STATE_REQUIRED','Сначала прочитайте состояние Bluetooth шлюза с этим токеном.');
   this.#verifiedState=false;
   // A timeout after this single send has an unknown outcome. Never retry a setter.
   const ack=await this.#exchange(method,{state:params.enable?1:0});
   if(!Array.isArray(ack)||ack.length!==1||ack[0]!=='ok')throw fail('MIIO_RESULT','Bluetooth шлюз вернул неизвестное подтверждение. Проверьте состояние.');
   const state=gatewayState(await this.#exchange('bleState',{}));
   if(state.enabled!==params.enable)throw fail('MIIO_READBACK','Изменение Bluetooth шлюза не подтверждено чтением.');
   this.#verifiedState=true;return state;
  }catch(error){
   this.#verifiedState=false;throw error;
  }finally{this.#busy=false;}
 }
 async #exchange(method,params){
  const hello=Buffer.alloc(32,0xff);hello.writeUInt16BE(0x2131,0);hello.writeUInt16BE(32,2);
  const handshake=await this.#roundTrip(hello);
  this.#header(handshake,32);
  // RD08 compares all eight identity bytes [4..12], including modern 64-bit DIDs.
  const deviceId=handshake.readBigUInt64BE(4),stamp=handshake.readUInt32BE(12),start=Date.now();
  if(deviceId===0n||deviceId===0xffffffffffffffffn||stamp===0||stamp===0xffffffff||(this.#deviceId!==null&&deviceId!==this.#deviceId))throw fail('MIIO_DEVICE','MIIO ответил другим идентификатором устройства.');
  if(this.#closed)throw fail('MIIO_CLOSED','Сеанс MIIO закрыт.');
  const id=this.#id=this.#id>=0x7ffffffe?1:this.#id+1;
  const plaintext=Buffer.from(JSON.stringify({id,method:METHODS[method],params})+'\0');
  let ciphertext;
  try{const cipher=createCipheriv('aes-128-cbc',this.#key,this.#iv);ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);}finally{plaintext.fill(0);}
  const header=Buffer.alloc(16);header.writeUInt16BE(0x2131);header.writeUInt16BE(32+ciphertext.length,2);header.writeBigUInt64BE(deviceId,4);header.writeUInt32BE(stamp,12);
  const packet=Buffer.concat([header,md5(Buffer.concat([header,this.#token,ciphertext])),ciphertext]);
  const reply=await this.#roundTrip(packet);
  this.#header(reply);
  if(reply.length<=32||(reply.length-32)%16!==0||reply.readBigUInt64BE(4)!==deviceId||Math.abs(reply.readUInt32BE(12)-(stamp+Math.floor((Date.now()-start)/1000)))>60)throw fail('MIIO_RESPONSE','Неверные устройство, время или длина ответа MIIO.');
  const expected=md5(Buffer.concat([reply.subarray(0,16),this.#token,reply.subarray(32)]));
  if(!timingSafeEqual(expected,reply.subarray(16,32)))throw fail('MIIO_AUTH','Подпись MIIO не совпала. Проверьте токен этого устройства.');
  let decoded;
  try{
   const decipher=createDecipheriv('aes-128-cbc',this.#key,this.#iv);
   decoded=Buffer.concat([decipher.update(reply.subarray(32)),decipher.final()]);
   const body=JSON.parse(decoded.toString('utf8').replace(/\0+$/,''));
   if(!plain(body)||body.id!==id||Object.keys(body).some(k=>!['id','result','error'].includes(k))||('error'in body&&'result'in body))throw fail('MIIO_RESPONSE','Неверная структура или идентификатор ответа MIIO.');
   if('error'in body)throw fail('MIIO_REMOTE',`Bluetooth RPC отклонён устройством${plain(body.error)&&Number.isInteger(body.error.code)?` (${body.error.code})`:''}.`);
   if(!Object.hasOwn(body,'result'))throw fail('MIIO_RESPONSE','MIIO не вернул результат.');
   this.#deviceId=deviceId;return body.result;
  }catch(error){
   if(typeof error.code==='string'&&error.code.startsWith('MIIO_'))throw error;
   throw fail('MIIO_RESPONSE','Не удалось проверить зашифрованный ответ MIIO.');
  }finally{decoded?.fill(0);}
 }
 #header(packet,length){
  if(packet.length<32||packet.length>MAX_PACKET||packet.readUInt16BE(0)!==0x2131||packet.readUInt16BE(2)!==packet.length||(length!==undefined&&packet.length!==length))throw fail('MIIO_RESPONSE','Некорректный заголовок MIIO.');
 }
 #roundTrip(packet){
  if(this.#closed)return Promise.reject(fail('MIIO_CLOSED','Сеанс MIIO закрыт.'));
  return new Promise((resolve,reject)=>{
   const socket=dgram.createSocket('udp4');let done=false,timer;
   const finish=(error,reply)=>{
    if(done)return;done=true;clearTimeout(timer);this.#sockets.delete(socket);socket.removeAllListeners();
    try{socket.close();}catch{}
    packet.fill(0);if(error)reject(error);else resolve(reply);
   };
   this.#sockets.set(socket,finish);
   socket.on('error',()=>finish(fail('MIIO_NETWORK','Ошибка локального UDP соединения MIIO.')));
   socket.on('message',(reply,peer)=>{
    if(peer.address!==this.#host||peer.port!==PORT)return;
    if(reply.length>MAX_PACKET)return finish(fail('MIIO_RESPONSE','Ответ MIIO превышает допустимый размер.'));
    finish(null,reply);
   });
   timer=setTimeout(()=>finish(fail('MIIO_TIMEOUT','MIIO не ответил. Изменение могло примениться; проверьте состояние перед повтором.')),this.#timeout);
   try{socket.send(packet,PORT,this.#host,error=>{if(error)finish(fail('MIIO_NETWORK','Не удалось отправить локальный запрос MIIO.'));});}
   catch{finish(fail('MIIO_NETWORK','Не удалось отправить локальный запрос MIIO.'));}
  });
 }
}
