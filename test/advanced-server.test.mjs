import test from 'node:test';
import assert from 'node:assert/strict';
import {createPanel,Router} from '../server.mjs';
import {fakeRouter,testConfig} from './fixture.mjs';
test('Advanced server binds jobs, log deletion, whitelist authorization and plugin files to its session',async()=>{
 const router=fakeRouter(),{server,origin}=await createPanel({config:testConfig,router,port:18655,demo:true});
 try{
  const html=await(await fetch(origin)).text(),csrf=html.match(/name="panel-csrf" content="([a-f0-9]+)"/)[1];
  const headers={'X-Panel-CSRF':csrf,'Content-Type':'application/json'};
  const post=(path,data)=>fetch(origin+'/api/'+path,{method:'POST',headers,body:JSON.stringify(data)});
  assert.equal((await fetch(origin+'/api/plugin-package',{method:'POST',headers:{'X-Panel-CSRF':csrf,'Content-Type':'application/octet-stream'},body:Buffer.alloc(30)})).status,401);
  const login=await post('login',{password:'panel-test'});headers.Cookie=login.headers.get('set-cookie').split(';')[0];
  assert.equal((await post('scanner',{op:'status'})).status,409);
  assert.equal((await post('scanner',{op:'start'})).status,200);
  assert.equal((await post('scanner',{op:'status'})).status,200);
  const other=await fetch(origin+'/api/login',{method:'POST',headers:{'X-Panel-CSRF':csrf,'Content-Type':'application/json'},body:JSON.stringify({password:'panel-test'})}),otherHeaders={...headers,Cookie:other.headers.get('set-cookie').split(';')[0]};
  assert.equal((await fetch(origin+'/api/scanner',{method:'POST',headers:otherHeaders,body:JSON.stringify({op:'stop'})})).status,409);
  assert.equal((await fetch(origin+'/api/logs?type=other',{headers})).status,400);
  assert.equal((await fetch(origin+'/api/logs?type=risk&days=7&limit=25',{headers})).status,200);
  assert.equal((await post('preview',{action:'logDelete',data:{ids:[99]}})).status,400);
  const selected=await post('preview',{action:'logDelete',data:{ids:[1]}});assert.equal(selected.status,200);
  const whitelist=await post('preview',{action:'urlWhitelistAdd',data:{url:'example.net'}}),plan=await whitelist.json();
  assert.equal(whitelist.status,200);assert(!JSON.stringify(plan).includes('fixture-authorization'));
  const applied=await post('apply',{ticket:plan.ticket});assert.equal(applied.status,422,'Native code0 without readback must not be reported as successful add');
  const malformed=await fetch(origin+'/api/plugin-package',{method:'POST',headers:{...headers,'Content-Type':'application/octet-stream'},body:Buffer.alloc(30)});assert.equal(malformed.status,400);
  assert.equal((await post('preview',{action:'pluginInstall',data:{sha256:'forged'}})).status,409);
  const bundle=await fetch(origin+'/api/plugin-example',{headers});assert.equal(bundle.status,200);assert.equal(Buffer.from(await bundle.arrayBuffer()).readUInt32LE(0),0x04034b50);
  assert.equal((await fetch(origin+'/api/mesh-add-status',{headers})).status,409);
  const discovery=await(await fetch(origin+'/api/mesh-discovery',{headers})).json();assert.deepEqual(discovery.list,[]);assert(!router.writes.some(w=>w.route==='xqnetwork/scan_mesh_node'));
 }finally{await new Promise(resolve=>server.close(resolve));}
});
test('Router refuses untrusted packages before starting any upload',async()=>{
 const router=new Router(testConfig);let calls=0;router.request=async()=>{calls++;return'{"code":0}';};
 try{await assert.rejects(router.uploadPlugin('fake-session',Buffer.alloc(30)));assert.equal(calls,0);}finally{router.agent.destroy();}
});
