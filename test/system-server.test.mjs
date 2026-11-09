import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createDecipheriv} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {Router,createPanel} from '../server.mjs';
import {fakeRouter,testConfig} from './fixture.mjs';
function backupFixture(){
 const blocks=[];for(const[name,body]of [['cfg_backup.des','["mi_wifi_info"]'],['cfg_backup.mbu','synthetic encrypted placeholder']]){
  const head=Buffer.alloc(512),data=Buffer.from(body);head.write(name);head.write(data.length.toString(8).padStart(11,'0')+'\0',124);head.fill(32,148,156);head[156]=48;
  head.write(head.reduce((sum,value)=>sum+value,0).toString(8).padStart(6,'0')+'\0 ',148);blocks.push(head,data,Buffer.alloc(512-data.length));
 }return gzipSync(Buffer.concat([...blocks,Buffer.alloc(1024)]));
}
test('Password encryption matches the native dual-hash AES protocol without revealing either password',async()=>{
 const router=new Router(testConfig),salt='protocol-public-salt',old='test-old-password',next='test-new-password';
 router.request=async()=>`key: '${salt}'\nvar deviceId = '02:00:00:00:00:01'`;
 router.api=async()=>({hardware:'RD08',newEncryptMode:1});
 const hash=(value,mode)=>createHash(mode).update(value).digest('hex');
 try{
  const params=await router.preparePassword(old,next);assert.match(params.nonce,/^0_02:00:00:00:00:01_\d+_\d+$/);
  assert.equal(params.oldPwd,hash(params.nonce+hash(old+salt,'sha256'),'sha256'));
  for(const[mode,key]of [['sha1','newPwd'],['sha256','newPwd256']]){
   const cipher=createDecipheriv('aes-128-cbc',Buffer.from(hash(old+salt,mode).slice(0,32),'hex'),Buffer.from('64175472480004614961023454661220','hex'));
   assert.equal(Buffer.concat([cipher.update(Buffer.from(params[key],'base64')),cipher.final()]).toString(),hash(next+salt,mode));
  }
  assert(!JSON.stringify(params).includes(old));assert(!JSON.stringify(params).includes(next));
 }finally{router.agent.destroy();}
});
test('File transport selects the native infile route and enforces its multipart size boundary',async()=>{
 const router=new Router(testConfig),calls=[];let infile=1;
 router.api=async()=>({code:0,system:{infileupload:infile}});
 router.request=async(path,method,body,binary,options)=>{calls.push({path,method,body,options});return'{"code":0}';};
 try{
  await router.uploadImage('abcd','xqsystem/upload_rom',Buffer.alloc(60000));assert.equal(calls[0].path,'/uploadfile/cgi-bin/luci/;stok=abcd/api/xqsystem/upload_rom');assert(calls[0].body.includes('filename="firmware.bin"'));
  infile=0;await assert.rejects(router.uploadImage('abcd','xqsystem/upload_rom',Buffer.alloc(60000)),e=>e.status===413);assert.equal(calls.length,1);
  await router.uploadImage('abcd','misystem/c_upload',backupFixture());assert.equal(calls[1].path,'/cgi-bin/luci/;stok=abcd/api/misystem/c_upload');
  await assert.rejects(router.uploadImage('abcd','xqsystem/arbitrary',Buffer.alloc(20)));assert.equal(calls.length,2);
 }finally{router.agent.destroy();}
});
test('Whitelist permission uses the native TLS listener without a vendor session in its URL',async()=>{
 const router=new Router(testConfig);let issued=true;
 router.request=async(path,method,params,binary,options)=>{assert.equal(path,'/cgi-bin/luci/url_fw');assert.deepEqual(options,{host:'example.net',port:8900});return `data: {url:'example.net', session:'${issued?'fixture-authorization':'0'}'}`;};
 try{assert.equal(await router.whitelistSession('abcd','example.net'),'fixture-authorization');issued=false;await assert.rejects(router.whitelistSession('abcd','example.net'),e=>e.status===422);}finally{router.agent.destroy();}
});
test('System controls remain explicit, password apply is one-use and ends every panel session',async()=>{
 const router=fakeRouter();let prepared=0,loggedOut=0;
 router.preparePassword=async()=>{prepared++;return {nonce:'fixture-nonce',oldPwd:'fixture-secret-hash',newPwd:'fixture-ciphertext',newPwd256:'fixture-ciphertext-256'};};
 router.logout=async()=>{loggedOut++;};
 const {server,origin}=await createPanel({config:testConfig,router,port:18656,demo:true});
 try{
  const html=await(await fetch(origin)).text(),csrf=html.match(/name="panel-csrf" content="([a-f0-9]+)"/)[1];
  const headers={'X-Panel-CSRF':csrf,'Content-Type':'application/json'};
  const post=(path,data,h=headers)=>fetch(origin+'/api/'+path,{method:'POST',headers:h,body:JSON.stringify(data)});
  assert.equal((await fetch(origin+'/api/system-file?kind=restore',{method:'POST',headers:{...headers,'Content-Type':'application/octet-stream'},body:Buffer.alloc(20)})).status,401);
  const login=await post('login',{password:'panel-test'});headers.Cookie=login.headers.get('set-cookie').split(';')[0];
  const other=await post('login',{password:'panel-test'},{'X-Panel-CSRF':csrf,'Content-Type':'application/json'}),otherCookie=other.headers.get('set-cookie').split(';')[0];
  assert.equal((await(await fetch(origin+'/api/timezones',{headers})).json()).length,113);
  assert.equal((await(await fetch(origin+'/api/system-stage',{headers})).json()),null);
  assert.equal((await post('preview',{action:'systemFileStage',data:{sha256:'forged'}})).status,409);
  assert.equal((await post('preview',{action:'bleEnable',data:{on:1}})).status,409);
  assert.equal((await post('miio-connect',{token:'not-a-token'})).status,400);
  const demoMiio=await post('miio-connect',{token:'a'.repeat(32)});assert.equal(demoMiio.status,422);assert.match((await demoMiio.json()).error,/демонстрации/);
  assert.equal(router.writes.length,0);
  assert.equal((await post('preview',{action:'adminPassword',data:{oldPassword:'old-test-password',newPassword:'short',repeatPassword:'short'}})).status,400);assert.equal(prepared,0);
  const preview=await(await post('preview',{action:'adminPassword',data:{oldPassword:'old-test-password',newPassword:'new-test-password',repeatPassword:'new-test-password'}})).json();
  assert(preview.ticket);const serialized=JSON.stringify(preview);for(const secret of ['old-test-password','new-test-password','fixture-secret-hash','fixture-ciphertext'])assert(!serialized.includes(secret));
  assert.equal(router.writes.length,0);
  const applied=await post('apply',{ticket:preview.ticket});assert.equal(applied.status,200);assert.equal((await applied.json()).reauth,true);
  assert.equal(router.writes.length,1);assert.equal(router.writes[0].route,'xqsystem/set_name_password');assert.equal(loggedOut,2);
  assert.equal((await post('apply',{ticket:preview.ticket})).status,401);
  assert.equal((await fetch(origin+'/api/last-change',{headers:{...headers,Cookie:otherCookie}})).status,401);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
test('Restore staging needs local preflight, explicit upload and an un-replaced one-use native stage',async()=>{
 const router=fakeRouter(),uploads=[];router.uploadImage=async(stok,route,bytes)=>{uploads.push({route,bytes:bytes.length});return{code:0,des:{keys:{mi_wifi_info:'Wi-Fi'}}};};
 const {server,origin}=await createPanel({config:testConfig,router,port:18657,demo:true});
 try{
  const html=await(await fetch(origin)).text(),csrf=html.match(/name="panel-csrf" content="([a-f0-9]+)"/)[1],base={'X-Panel-CSRF':csrf,'Content-Type':'application/json'};
  const post=(path,data,headers=base)=>fetch(origin+'/api/'+path,{method:'POST',headers,body:JSON.stringify(data)});
  const headers=[];for(let i=0;i<2;i++){const login=await post('login',{password:'panel-test'});headers.push({...base,Cookie:login.headers.get('set-cookie').split(';')[0]});}
  const upload=(bytes,h)=>fetch(origin+'/api/system-file?kind=restore',{method:'POST',headers:{...h,'Content-Type':'application/octet-stream'},body:bytes});
  assert.equal((await(await upload(Buffer.alloc(20),headers[0])).json()).valid,false);assert.equal(uploads.length,0);
  const applyStage=async h=>{
   const inspected=await(await upload(backupFixture(),h)).json();assert(inspected.valid);assert(!JSON.stringify(inspected).includes('synthetic encrypted placeholder'));
   const preview=await(await post('preview',{action:'systemFileStage',data:{sha256:inspected.sha256}},h)).json();assert(preview.ticket);
   const response=await post('apply',{ticket:preview.ticket},h);assert.equal(response.status,200);assert((await response.json()).stage.reply);
   assert.equal((await post('apply',{ticket:preview.ticket},h)).status,409);
  };
  await applyStage(headers[0]);assert.equal(uploads.length,1);assert.equal(router.writes.length,0);
  const firstPlan=await(await post('preview',{action:'restoreApply',data:{confirm:'ВОССТАНОВИТЬ RD08',keys:['mi_wifi_info']}},headers[0])).json();assert(firstPlan.ticket);
  await applyStage(headers[1]);assert.equal((await post('apply',{ticket:firstPlan.ticket},headers[0])).status,409);
  const nextPlan=await(await post('preview',{action:'restoreApply',data:{confirm:'ВОССТАНОВИТЬ RD08',keys:['mi_wifi_info']}},headers[1])).json();assert(nextPlan.ticket);
  assert.equal((await post('apply',{ticket:nextPlan.ticket},headers[1])).status,200);
  assert.equal(router.writes.filter(x=>x.route==='misystem/c_restore').length,1);assert.equal(uploads.length,2);assert(uploads.every(x=>x.route==='misystem/c_upload'));
 }finally{await new Promise(resolve=>server.close(resolve));}
});
