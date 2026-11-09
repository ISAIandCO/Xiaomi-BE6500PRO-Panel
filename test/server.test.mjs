import test from 'node:test';
import assert from 'node:assert/strict';
import { createPanel } from '../server.mjs';
import { GROUPS } from '../core.mjs';
import {fakeRouter,testConfig} from './fixture.mjs';
test('Local server enforces sessions, CSRF, fixed reads and single-use apply tickets',async()=>{
 const router=fakeRouter();const {server,origin}=await createPanel({config:testConfig,router,port:18652,demo:true});
 try{
  const page=await(await fetch(origin)).text();const csrf=page.match(/name="panel-csrf" content="([a-f0-9]+)"/)[1];
  const headers={'X-Panel-CSRF':csrf,'Content-Type':'application/json'};
  assert.equal((await fetch(origin+'/api/read?group=overview')).status,403);
  assert.equal((await fetch(origin+'/api/read?group=overview',{headers})).status,401);
  const badOrigin=await fetch(origin+'/api/info',{headers:{...headers,Origin:'https://unrelated.example'}});assert.equal(badOrigin.status,403);
  const login=await fetch(origin+'/api/login',{method:'POST',headers,body:JSON.stringify({password:'panel-test'})});assert.equal(login.status,200);
  headers.Cookie=login.headers.get('set-cookie').split(';')[0];
  for(const group of Object.keys(GROUPS)){
   const r=await fetch(origin+'/api/read?group='+group,{headers});assert.equal(r.status,200,group);const text=await r.text();assert(!text.includes('not-a-real-network-key'));assert(!text.includes('do-not-expose'));
   for(const [key,value]of Object.entries(JSON.parse(text)))assert(!value.error,`${group}/${key}`);
  }
  assert.equal(router.writes.length,0,'Browsing a tab must not invoke a mutating API');
  assert.equal((await fetch(origin+'/api/read?group=../xqsystem/reset',{headers})).status,404);
  const preview=await(await fetch(origin+'/api/preview',{method:'POST',headers,body:JSON.stringify({action:'mlo',data:{on:1}})})).json();assert(preview.ticket);assert.equal(router.writes.length,0);
  const apply=()=>fetch(origin+'/api/apply',{method:'POST',headers,body:JSON.stringify({ticket:preview.ticket})});
  assert.equal((await apply()).status,200);assert.equal(router.writes.length,1);assert.equal(router.writes[0].route,'xqnetwork/set_hostap_mlo');assert.equal((await apply()).status,409);assert.equal(router.writes.length,1);
  await fetch(origin+'/api/logout',{method:'POST',headers,body:'{}'});assert.equal((await fetch(origin+'/api/read?group=overview',{headers})).status,401);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
