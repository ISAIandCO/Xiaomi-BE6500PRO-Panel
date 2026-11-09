import test from 'node:test';
import assert from 'node:assert/strict';
import {buildPlan,publicData,GROUPS} from '../core.mjs';
import {createPanel,normalizeRead,Router} from '../server.mjs';
import {fixture,fakeRouter,testConfig} from './fixture.mjs';

test('Guest Wi-Fi uses the guest implementation instead of the no-op set_wifi branch',()=>{
 const plan=buildPlan('guest',{on:1,ssid:'Visitors',encryption:'psk2',password:''},fixture);
 assert.equal(plan.steps[0].path,'xqnetwork/set_wifi_without_restart');assert.equal(plan.steps[0].params.wifiIndex,'3');
 assert.equal(plan.steps[0].params.pwd,'not-a-real-network-key');assert(!JSON.stringify(plan.changes).includes('not-a-real-network-key'));
 assert.throws(()=>buildPlan('guest',{on:1,ssid:'Visitors',encryption:'ccmp',password:'fixture-password'},fixture));
 assert.throws(()=>buildPlan('guest',{on:1,ssid:'Visitors',encryption:'psk2',password:''},{'xqnetwork/wifi_diag_detail_all':{code:0,info:[]}}));
});
test('Schedules add one interval, remove only a known rule, and reject overnight ambiguity',()=>{
 const context={...fixture,'misystem/mipctl_get_deny_time':{code:0,time_list:[{id:'1_600_660_127',start:600,end:660,enable:[1,1,1,1,1,1,1]}]}};
 const plan=buildPlan('parentalSchedule',{user_id:1,start:'22:00',end:'23:00',days:['0','1','2','3','4']},context);
 assert.deepEqual(JSON.parse(plan.steps[0].params.opt_list)[0].time_list,[{start:1320,end:1380,enable:[1,1,1,1,1,0,0]}]);
 const remove=buildPlan('parentalSchedule',{user_id:1,remove:'1_600_660_127'},context);
 assert.deepEqual(JSON.parse(remove.steps[0].params.opt_list)[0].time_list,[{id:'1_600_660_127'}]);
 assert.throws(()=>buildPlan('parentalSchedule',{user_id:1,start:'23:00',end:'06:00',days:[0]},context));
 assert.throws(()=>buildPlan('parentalSchedule',{user_id:1,remove:'unknown'},context));
});
test('Web management ACL preserves this computer and clock rejects invalid dates',()=>{
 const self=fixture['xqsystem/device_mac'].mac;
 assert.equal(buildPlan('webAccess',{on:1},fixture).steps[0].params.mac,self);
 assert.throws(()=>buildPlan('webAccessEntry',{mac:self,on:0},{...fixture,'misystem/web_access_info':{code:0,open:true}}));
 assert.throws(()=>buildPlan('clock',{time:'2026-02-30T10:00:00'},fixture));
 assert.equal(buildPlan('clock',{time:'2026-11-08T15:00:00'},fixture).steps[0].params.time,'2026-11-08 15:00:00');
});

test('IoT editing preserves both secrets in server memory, never in previews',()=>{
 const data={on:1,wifi5mode:1,ssid2g:'Sensors',ssid5g:'Sensors 5',encryption2g:'psk2',encryption5g:'ccmp',password2g:'',password5g:''};
 const plan=buildPlan('iot',data,fixture);
 assert.equal(plan.steps[0].path,'xqnetwork/set_iotwifi_info');assert.equal(plan.steps[0].params.password2g,'not-a-real-network-key');
 assert(!JSON.stringify(plan.changes).includes('not-a-real-network-key'));
 assert.throws(()=>buildPlan('iot',{...data,password2g:'short'},fixture));
 assert.throws(()=>buildPlan('iot',{...data,ssid2g:'я'.repeat(17)},fixture));
});
test('ACL refuses to lock out the computer running the panel',()=>{
 const self=fixture['xqsystem/device_mac'].mac;
 assert.throws(()=>buildPlan('acl',{on:1,model:1},fixture),/белого|белый/);
 const white={...fixture,'xqnetwork/wifi_macfilter_info':{code:0,model:1,enable:1,macfilter:[{mac:self}]}};
 assert.equal(buildPlan('acl',{on:1,model:1},white).steps[0].params.enable,'1');
 assert.throws(()=>buildPlan('aclEntry',{model:1,on:0,mac:self},white),/отключит/);
 assert.throws(()=>buildPlan('deviceAccess',{mac:self,on:0},fixture),/компьютер/);
 assert.throws(()=>buildPlan('deviceAccess',{mac:'02:00:00:00:00:99',on:1},fixture),/отсутствует/);
 assert.throws(()=>buildPlan('aclEntry',{model:0,on:1,mac:'FF:FF:FF:FF:FF:FF'},fixture));
});
test('Device settings use the stock name, permission and KB/s contracts',()=>{
 const mac='02:00:00:00:00:02';
 assert.deepEqual(buildPlan('deviceAccess',{mac,on:0},fixture).steps[0].params,{mac,wan:'0'});
 const limits=JSON.parse(buildPlan('deviceQos',{mac,download:128,upload:64},fixture).steps[0].params.data);
 assert.deepEqual(limits,[{mac,maxup:'64',maxdown:'128'}]);
 assert.throws(()=>buildPlan('deviceName',{mac,name:'bad;command'},fixture));
 assert.equal(buildPlan('deviceName',{mac,name:'Телефон'},fixture).steps[0].path,'xqsystem/set_device_nickname');
 const off={...fixture,'misystem/qos_info':{...fixture['misystem/qos_info'],status:{on:0}}};
 assert.throws(()=>buildPlan('deviceQos',{mac,download:128,upload:64},off),/QoS/);
});
test('Full DHCP pools validate subnet boundaries, router address and pool size',()=>{
 const context={...fixture,'xqnetwork/lan_info':{code:0,info:{ipv4:[{ip:'192.168.28.1',mask:'255.255.252.0'}]}}};
 const data={on:1,startip:'192.168.28.5',endip:'192.168.31.200',minutes:720};
 const p=buildPlan('dhcp',data,context);assert.equal(p.steps[0].params.endip,'192.168.31.200');assert.equal(p.wait,30);
 for(const bad of [{startip:'192.168.28.0'},{endip:'192.168.31.255'},{endip:'192.168.32.1'},{startip:'192.168.28.1'},{endip:'192.168.31.254'}])assert.throws(()=>buildPlan('dhcp',{...data,...bad},context));
});
test('IPv6 firewall code is a value and advanced IPv6 uses exact field names',()=>{
 assert.deepEqual(normalizeRead('xqnetwork/get_ipv6_firewall',{code:'1'}),{code:0,mode:'1'});
 assert.deepEqual(normalizeRead('misystem/status',{code:1}),{code:1});
 const p=buildPlan('ipv6',{mode:'pppoev6',usePPPoEv4:0,username:'user',password:'fixture-password',prefixlen:64,nat6:0},fixture);
 assert.equal(p.steps[0].params.use_pppoev4,'0');assert.equal(p.steps[0].params.nat6_enabled,'0');
 const tunnel=buildPlan('ipv6',{mode:'6in4',peeraddr:'198.51.100.1',ip6addr:'2001:db8::2',prefix:'2001:db8:1::',prefixlen:64},fixture);
 assert.equal(tunnel.steps[0].params.peeraddr,'198.51.100.1');assert.equal(tunnel.steps[0].params.ip6prefix,'2001:db8:1::');
 assert.throws(()=>buildPlan('ipv6',{mode:'static',ip6addr:'not-ipv6'},fixture));
 assert.equal(buildPlan('gateway',{on:1},fixture).steps[0].params.on,'1');
 assert.equal(buildPlan('wifiAx',{on:1},fixture).steps[0].params.user_confirm,'1');
 assert.equal(buildPlan('beamforming',{on:1},fixture).steps[0].params.txbf,'3');
});
test('NAT ranges and Mesh modes reject invalid or unimplemented values',()=>{
 const data={name:'Media',fport:8000,tport:8010,proto:3,ip:'192.168.31.110'};
 const p=buildPlan('natRange',data,fixture);assert.equal(p.steps[0].path,'xqsystem/add_range_redirect');assert.equal(p.steps[0].params.fport,'8000');assert.equal(p.steps[1].path,'xqsystem/redirect_apply');
 assert.throws(()=>buildPlan('natRange',{...data,tport:7999},fixture));
 assert.equal(buildPlan('backhaul',{mode:'wired'},fixture).steps[0].params.bhmode,'wired');
 assert.throws(()=>buildPlan('backhaul',{mode:'wireless'},fixture));
});
test('Parental profiles use a bounded operation list with boolean pause values',()=>{
 const p=buildPlan('parentalPause',{user_id:1,on:0},fixture);assert.deepEqual(JSON.parse(p.steps[0].params.opt_list),[{opt:'mipctl_set_temp_deny',user_id:1,deny:false}]);
 assert.throws(()=>buildPlan('parentalDelete',{user_id:99},fixture),/не существует/);
 assert.throws(()=>buildPlan('parentalHosts',{user_id:1,domains:'https://example.net/path'},fixture));
 const devices=buildPlan('parentalDevices',{user_id:1,macs:'02:00:00:00:00:02\n02:00:00:00:00:02'},fixture);
 assert.deepEqual(JSON.parse(devices.steps[0].params.opt_list)[0].devices,['02:00:00:00:00:02']);
});
test('VPN and DDNS edit preserve credentials without putting them in UI data',()=>{
 const vpn=buildPlan('vpnEdit',{id:'vpn1',oname:'Home',server:'vpn.example.net',username:'user',password:'',proto:'l2tp'},fixture);
 assert.equal(vpn.steps[0].params.id,'vpn1');assert.equal(vpn.steps[0].params.password,'do-not-expose');
 assert.throws(()=>buildPlan('vpnEdit',{id:'missing'},fixture));
 const ctx={...fixture,'xqnetwork/ddns':{code:0,list:[{id:8,password:'fixture-token',enable:1}]}};
 const ddns=buildPlan('ddnsEdit',{id:8,domain:'home.example.net',wanindex:'WAN1',iptype:0,password:''},ctx);
 assert.equal(ddns.steps[0].path,'xqnetwork/ddns_edit');assert.equal(ddns.steps[0].params.password,'fixture-token');
 assert(!JSON.stringify(publicData({url:'/cgi-bin/luci/;stok=abc123/',ssecurity:'abc',password2g:'pw',nested:{access_token:'token'}})).includes('abc'));
});
test('All visible read groups have explicit fixtures, not hidden failures',()=>{
 for(const routes of Object.values(GROUPS))for(const route of Object.values(routes))assert(Object.hasOwn(fixture,route),route);
});

test('Security plans validate every switch and preserve unrelated filter configuration',()=>{
 for(const [action,path]of [['attackScan','set_scan'],['attackDos','set_dos'],['attackRpfilter','set_rpfilter']]){
  assert.deepEqual(buildPlan(action,{on:1},fixture).steps,[{path:'anti_attack/'+path,method:'POST',params:{enable:'1'}}]);
  assert.throws(()=>buildPlan(action,{on:'1;reboot'},fixture));
 }
 const plan=buildPlan('contentFilter',{on:0,autoUpdate:1},fixture);
 assert.deepEqual(plan.steps,[{path:'url_fw/update_status',method:'POST',params:{enable:'0',auto_update:'1'}}]);
 assert.throws(()=>buildPlan('contentFilter',{on:1},fixture));
 assert.throws(()=>buildPlan('contentFilter',{on:1,autoUpdate:2},fixture));
 assert.throws(()=>buildPlan('uploadPlug',{image:'anything'},fixture));
});

test('Scanner password-strength metadata survives redaction while real credentials stay hidden',()=>{
 const value=publicData(normalizeRead('sec_center/overview',{code:0,config_scanner:{wifi_passwd_secure:{enable_scan:1,password:'hidden'}}}));
 assert.equal(value.config_scanner.wifiKeyStrength.enable_scan,1);assert(!JSON.stringify(value).includes('hidden'));
 assert(!JSON.stringify(publicData(normalizeRead('config_scanner/overview',{wifi_passwd_secure:'hidden'}))).includes('hidden'));
});
test('Expanded server reads never write, preview scrubs originals, unsupported reads block saving',async()=>{
 const router=fakeRouter();const {server,origin}=await createPanel({config:testConfig,router,port:18653,demo:true});
 try{
  const html=await(await fetch(origin)).text();const headers={'X-Panel-CSRF':html.match(/name="panel-csrf" content="([a-f0-9]+)"/)[1],'Content-Type':'application/json'};
  const login=await fetch(origin+'/api/login',{method:'POST',headers,body:JSON.stringify({password:'panel-test'})});headers.Cookie=login.headers.get('set-cookie').split(';')[0];
  const get=path=>fetch(origin+'/api/'+path,{headers});const post=(path,body)=>fetch(origin+'/api/'+path,{method:'POST',headers,body:JSON.stringify(body)});
  for(const group of ['iot','security','mesh','parental','diagnostics']){const r=await get('read?group='+group);assert.equal(r.status,200);const data=await r.json();for(const value of Object.values(data))assert(!value.error,group);}
  const detail=await(await get('detail?kind=parental&user_id=1')).json();assert.deepEqual(detail.devices,['02:00:00:00:00:02']);
  assert.equal((await get('detail?kind=parental&user_id=99')).status,404);assert.equal(router.writes.length,0);
  const preview=await(await post('preview',{action:'iotPriority',data:{on:0}})).json();assert(preview.ticket);assert(!JSON.stringify(preview).includes('not-a-real-network-key'));
  assert.equal(router.writes.length,0);assert.equal((await post('apply',{ticket:preview.ticket})).status,200);
  assert.equal(router.writes.length,1);assert(!JSON.stringify(await(await get('last-change')).json()).includes('not-a-real-network-key'));
  const original=router.api;router.api=async(...args)=>args[1]==='xqnetwork/get_iotwifi_info'?{code:404}:original(...args);
  assert.equal((await post('preview',{action:'iotPriority',data:{on:1}})).status,422);assert.equal(router.writes.length,1);
  assert.equal((await post('preview',null)).status,400);
  router.api=async(...args)=>args[1]==='xqnetwork/set_wifi_ax'?{code:0,need_confirm:1}:original(...args);
  const dfs=await(await post('preview',{action:'wifiAx',data:{on:1}})).json();assert(dfs.ticket);
  const refused=await post('apply',{ticket:dfs.ticket});assert.equal(refused.status,409);assert.match((await refused.json()).error,/не подтверждено/);
  router.api=async(...args)=>args[1]==='xqnetwork/set_wifi_ax'?{code:0,cac_time:600}:original(...args);
  const cac=await(await post('preview',{action:'wifiAx',data:{on:1}})).json();assert(cac.ticket);
  assert.equal((await(await post('apply',{ticket:cac.ticket})).json()).wait,610);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
test('Backup transport rejects traversal and HTML instead of serving arbitrary router files',async()=>{
 const router=new Router(testConfig);router.api=async()=>({code:0,file:'../config.tar.gz'});
 await assert.rejects(router.backup({stok:'fixture'}),/имя/);
 router.api=async()=>({code:0,file:'2026-11-08--15:00:00.tar.gz'});router.request=async()=>Buffer.from('<html>login</html>');
 await assert.rejects(router.backup({stok:'fixture'}),/архив/);router.agent.destroy();
});
