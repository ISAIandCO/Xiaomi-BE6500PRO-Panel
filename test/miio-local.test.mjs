import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import dgram from 'node:dgram';
import {createCipheriv,createDecipheriv,createHash,timingSafeEqual} from 'node:crypto';
import {MiioLocal} from '../miio-local.mjs';

const host='192.168.31.1',token='0123456789abcdef0123456789abcdef',did=109876543210n,ts=1700000000;
const hash=b=>createHash('md5').update(b).digest(),secret=Buffer.from(token,'hex'),key=hash(secret),iv=hash(Buffer.concat([key,secret]));
function hello(id=did){const h=Buffer.alloc(32);h.writeUInt16BE(0x2131);h.writeUInt16BE(32,2);h.writeBigUInt64BE(id,4);h.writeUInt32BE(ts,12);return h;}
function encode(body,{id=did,timestamp=ts}={}){
 const c=createCipheriv('aes-128-cbc',key,iv),payload=Buffer.concat([c.update(JSON.stringify(body)+'\0'),c.final()]),h=hello(id).subarray(0,16);
 h.writeUInt16BE(32+payload.length,2);h.writeUInt32BE(timestamp,12);
 return Buffer.concat([h,hash(Buffer.concat([h,secret,payload])),payload]);
}
function decode(packet){
 assert.equal(packet.readUInt16BE(0),0x2131);assert.equal(packet.readUInt16BE(2),packet.length);assert.equal(packet.readBigUInt64BE(4),did);
 assert.equal(packet.readUInt32BE(12),ts);assert.ok(timingSafeEqual(hash(Buffer.concat([packet.subarray(0,16),secret,packet.subarray(32)])),packet.subarray(16,32)));
 const c=createDecipheriv('aes-128-cbc',key,iv);return JSON.parse(Buffer.concat([c.update(packet.subarray(32)),c.final()]).toString().replace(/\0+$/,''));
}
function fixture(t,responder,options={}){
 const sent=[],sockets=[];
 mock.method(dgram,'createSocket',kind=>{
  assert.equal(kind,'udp4');const socket=new EventEmitter();socket.closed=false;
  socket.close=()=>{socket.closed=true;};sockets.push(socket);
  socket.send=(packet,port,address,callback)=>{
   assert.equal(port,54321);assert.equal(address,host);const request=Buffer.from(packet);sent.push(request);
   callback(null);queueMicrotask(()=>{
    if(socket.closed)return;
    const response=request.length===32?(options.hello?.()??hello()):responder(decode(request),sent);
    if(response){options.beforeReply?.(socket,response);socket.emit('message',response,{address:host,port:54321});}
   });
  };
  return socket;
 });
 const client=new MiioLocal({host,token,deviceId:did.toString(),timeoutMs:100});
 t.after(()=>{client.close();mock.restoreAll();});return {client,sent,sockets};
}
test('fixed gateway getters authenticate frames and normalize only confirmed native shapes',async t=>{
 const {client,sent,sockets}=fixture(t,req=>{
  assert.deepEqual(req.params,{});assert.deepEqual(Object.keys(req).sort(),['id','method','params']);
  return encode({id:req.id,result:req.method==='miIO.ble_gateway_state'?{state:0}:{bt_gateway_version:'4.0.11_0007',app_version:'4.0.11_0007',app_sdk:'4.0.11_0007',build_feature:'BLE',cm_build_info:'stable'}});
 });
 assert.deepEqual(await client.getState(),{enabled:false});assert.deepEqual(await client.getVersion(),{version:'4.0.11_0007'});
 assert.equal(sent.length,4);assert.ok(sockets.every(s=>s.closed));
 assert.equal(JSON.stringify(client),'{}');assert.ok(!JSON.stringify(sent.map(b=>b.toString('hex'))).includes(token));
});
test('setter needs a verified getter, sends once, checks exact ack and fresh readback',async t=>{
 let state=0;const methods=[];
 const {client,sent}=fixture(t,req=>{
  methods.push(req.method);
  if(req.method==='miIO.ble_gateway_enable'){assert.deepEqual(req.params,{state:1});state=1;return encode({id:req.id,result:['ok']});}
  return encode({id:req.id,result:{state}});
 });
 await assert.rejects(client.setEnabled(true),{code:'MIIO_STATE_REQUIRED'});assert.equal(sent.length,0);
 await client.getState();assert.deepEqual(await client.setEnabled(true),{enabled:true});
 assert.deepEqual(methods,['miIO.ble_gateway_state','miIO.ble_gateway_enable','miIO.ble_gateway_state']);
});
test('setter timeout never retries and invalidates previously verified capability',async t=>{
 let enables=0;const {client}=fixture(t,req=>{if(req.method==='miIO.ble_gateway_enable'){enables++;return null;}return encode({id:req.id,result:{state:0}});});
 await client.getState();await assert.rejects(client.setEnabled(true),{code:'MIIO_TIMEOUT'});assert.equal(enables,1);
 await assert.rejects(client.setEnabled(true),{code:'MIIO_STATE_REQUIRED'});
});
test('setter refuses unexpected acknowledgments and mismatched readback',async t=>{
 let ack=['ok'],state=0;const {client}=fixture(t,req=>encode({id:req.id,result:req.method==='miIO.ble_gateway_enable'?ack:{state}}));
 await client.getState();ack='ok';await assert.rejects(client.setEnabled(true),{code:'MIIO_RESULT'});
 await client.getState();ack=['ok'];await assert.rejects(client.setEnabled(true),{code:'MIIO_READBACK'});
});
test('token, host, device, methods and setter arguments are bounded before network',async()=>{
 for(const bad of ['127.0.0.1','8.8.8.8','example.com','169.254.1.1','192.168.31.255','10.0.0.0','172.32.0.1','[::1]'])assert.throws(()=>new MiioLocal({host:bad,token}),{code:'MIIO_CONFIG'});
 for(const bad of ['',token+'00','g'.repeat(32),'0'.repeat(32),'f'.repeat(32)])assert.throws(()=>new MiioLocal({host,token:bad}),{code:'MIIO_CONFIG'});
 assert.throws(()=>new MiioLocal({host,token,deviceId:'18446744073709551616'}),{code:'MIIO_CONFIG'});
 const client=new MiioLocal({host,token});
 for(const [method,params] of [['miIO.ble_gateway_state',{}],['__proto__',{}],['bleState',{miio_client_from:'cloud'}],['bleEnable',{enable:1}],['bleEnable',{enable:true,extra:1}],['bleState',[]]])await assert.rejects(client.request(method,params),{code:'MIIO_METHOD'});
 client.close();await assert.rejects(client.getState(),{code:'MIIO_CLOSED'});
});
test('reply corruption, wrong id/device/timestamp and remote errors fail closed',async t=>{
 let mutate=(b)=>b;const {client}=fixture(t,req=>mutate(encode({id:req.id,result:{state:1}}),req));
 const cases=[
  [b=>{b[16]^=1;return b;},'MIIO_AUTH'],
  (b,req)=>encode({id:req.id+1,result:{state:1}}),
  (b,req)=>encode({id:req.id,result:{state:1}},{id:did+1n}),
  (b,req)=>encode({id:req.id,result:{state:1}},{timestamp:ts+61}),
  (b,req)=>encode({id:req.id,result:{state:2}}),
  (b,req)=>encode({id:req.id,result:{state:1,other:true}}),
  (b,req)=>encode({id:req.id,error:{code:-30015,message:token}}),
 ];
 for(const item of cases){const [fn,code]=Array.isArray(item)?item:[item,null];mutate=fn;await assert.rejects(client.getState(),error=>{assert.ok(error.code.startsWith('MIIO_'));if(code)assert.equal(error.code,code);assert.ok(!error.message.includes(token));return true;});}
});
test('a different hello DID is rejected before any encrypted method is sent',async t=>{
 const {client,sent}=fixture(t,()=>{throw Error('must not send RPC');},{hello:()=>hello(did+1n)});
 await assert.rejects(client.getState(),{code:'MIIO_DEVICE'});assert.equal(sent.length,1);
});
test('foreign peers are ignored while malformed and oversized router datagrams are rejected',async t=>{
 let transform=b=>b;const {client}=fixture(t,req=>transform(encode({id:req.id,result:{state:0}})),{
  beforeReply(socket){socket.emit('message',Buffer.from('untrusted'),{address:'192.168.31.2',port:54321});socket.emit('message',Buffer.from('untrusted'),{address:host,port:54322});}
 });
 assert.deepEqual(await client.getState(),{enabled:false});
 for(const fn of [b=>Buffer.alloc(5000),b=>b.subarray(0,31),b=>{b.writeUInt16BE(0,0);return b;},b=>{b.writeUInt16BE(b.length+16,2);return b;}]){transform=fn;await assert.rejects(client.getState(),{code:'MIIO_RESPONSE'});}
});
test('logout closes pending sockets and rejects concurrent or later calls',async t=>{
 const {client,sockets}=fixture(t,()=>null,{hello:()=>null});
 const pending=client.getState();await assert.rejects(client.getVersion(),{code:'MIIO_BUSY'});client.close();
 await assert.rejects(pending,{code:'MIIO_CLOSED'});assert.ok(sockets.every(s=>s.closed));
 await assert.rejects(client.getState(),{code:'MIIO_CLOSED'});
});
