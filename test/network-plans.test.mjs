import test from 'node:test';
import assert from 'node:assert/strict';
import {buildNetworkPlan,NETWORK_GROUPS} from '../network-plans.mjs';

const self='02:00:00:00:00:01',client='02:00:00:00:00:02',node='02:00:00:00:00:03';
const context={
  'xqnetwork/get_wifi_weak':{code:0,info:[{},{}]},
  'xqnetwork/wifi_detail_all':{code:0,info:[{status:'1'},{status:'1'}]},
  'xqnetwork/get_mesh_switch':{code:0,enabled:0},
  'xqnetwork/get_roam_rssi_threshold':{code:0,RoamRssiThreshold2G:'-60',RoamRssiThreshold5G:'-60'},
  'misystem/get_ps_service?service=multiwan':{code:0,multiwan:{enable:1,port_map:[{name:'WAN1',port:4},{name:'WAN2',port:3}]}},
  'xqnetwork/get_multiwan_dev_policies':{code:0,info:{dev_policies:[{mac:client,oname:'Phone',wan:'WAN1',manual:0}]}},
  'misystem/devicelist':{code:0,list:[{mac:self,name:'Panel'},{mac:client,name:'Phone'}]},
  'xqsystem/device_mac':{code:0,mac:self},
  'xqnetwork/wan_info':{code:0,info:{details:{wanType:'pppoe'}}},
  'xqnetwork/wan_info:WAN2':{code:0,info:{details:{wanType:'pppoe'}}},
  'misystem/qos_info':{code:0,status:{on:1},band:{download:500,upload:100}},
  meshBindingMac:client,
  'xqnetwork/get_sta_bindinfo':{code:0,bindinfo:{bind_mac:'none',bind_node:'none',bind_band:'none'},meshnode:[{mac:node,router_name:'Living room',support_accessCtl:1,wifiup:1}]},
  'misystem/child_mesh_infos':{code:0,childMeshInfos:[]},
  meshDiscovery:{at:Date.now(),result:{code:0,list:[{mac:node}]}},
  'misystem/mipctl_get_user_list':{code:0,user_list:[{user_id:1,user_name:'Child'}]},
  'misystem/feature_info':{apps:{mipctlv2_temp_allow:'1'}},
  'misystem/mipctl_get_temp_allow':{code:0,allow:false},
  'misystem/mipctl_get_app_antiaddict':{code:0,list:[{class_name:'games',enable:false,time_quota:120,app_list:[{name:'Game',enable:true}]}]},
};
const build=(action,data,ctx=context)=>buildNetworkPlan(action,data,ctx);
test('Weak-client policy uses stock dBm bounds and rejects unsafe threshold order',()=>{
  assert.deepEqual(build('weakWifi',{index:1,on:1,weak:-80,kick:-85}).steps[0].params,{wifiIndex:'1',weakenable:'1',weakthreshold:'-80',kickthreshold:'-85'});
  assert.equal(build('weakWifi',{index:2,on:0,weak:-60,kick:-70}).wait,30);
  for(const data of [{index:1,on:1,weak:0,kick:0},{index:2,on:1,weak:-90,kick:-90},{index:1,on:1,weak:-90,kick:-80},{index:3,on:1,weak:-80,kick:-90}])assert.throws(()=>build('weakWifi',data));
  assert.throws(()=>build('weakWifi',{index:1,on:1,weak:-80,kick:-85},{}));
});
test('Mesh special states are guarded and legacy thresholds target their separate setter',()=>{
  assert.deepEqual(build('meshSwitch',{on:1}).steps[0].params,{on:'1'});
  for(const enabled of [2,3,undefined])assert.throws(()=>build('meshSwitch',{on:0},{...context,'xqnetwork/get_mesh_switch':{code:0,enabled}}));
  assert.deepEqual(build('legacyRoaming',{rssi2g:-70,rssi5g:-65}).steps[0].params,{roamrssithreshold1:'-70',roamrssithreshold2:'-65'});
  assert.throws(()=>build('legacyRoaming',{rssi2g:-49,rssi5g:-65}));
});
test('Dual WAN rules use known records, validate destinations and require enabled second WAN',()=>{
  assert.deepEqual(build('multiwanDevice',{mac:client,wan:'WAN2',on:1}).steps[0].params,{mac:client,manual:'0',wan:'WAN2',oname:'Phone',opt:'0'});
  assert.equal(build('multiwanDevice',{mac:client,on:0}).steps[0].params.opt,'1');
  assert.throws(()=>build('multiwanDevice',{mac:node,on:0}));
  assert.throws(()=>build('multiwanDevice',{mac:node,on:1,manual:0,wan:'WAN1'}));
  assert.throws(()=>build('multiwanDevice',{mac:node,on:1,manual:1,wan:'WAN3',name:'New'}));
  assert.throws(()=>build('multiwanDevice',{mac:node,on:1,manual:1,wan:'WAN1',name:'$(bad)'}));
  assert.throws(()=>build('multiwanWeight',{wan1:100,wan2:100},{...context,'misystem/get_ps_service?service=multiwan':{code:0,multiwan:{enable:0}}}));
  assert.deepEqual(build('multiwanWeight',{wan1:100,wan2:10}).steps[0].params,{bandwidth_wan1:'100',bandwidth_wan2:'10'});
  for(const d of [{wan1:0,wan2:1},{wan1:101,wan2:1},{wan1:NaN,wan2:1},{wan1:true,wan2:1}])assert.throws(()=>build('multiwanWeight',d));
});
test('WAN lifecycle is explicit and PPPoE cannot be applied to DHCP or an unread WAN2',()=>{
  assert.equal(build('wanLink',{on:0}).steps[0].path,'xqnetwork/wan_down');
  assert.deepEqual(build('pppoeLink',{wan:'WAN2',on:1}).steps[0],{path:'xqnetwork/pppoe_start',method:'GET',params:{wan_name:'WAN2'}});
  assert.throws(()=>build('pppoeLink',{wan:'WAN1',on:1},{...context,'xqnetwork/wan_info':{code:0,info:{details:{wanType:'dhcp'}}}}));
  assert.throws(()=>build('pppoeLink',{wan:'WAN2',on:1},{...context,'xqnetwork/wan_info:WAN2':undefined}));
});
test('Guest QoS converts Mbps to fractions and never exposes its setter as an automatic read',()=>{
  assert.deepEqual(build('guestQos',{download:100,upload:10}).steps[0],{path:'misystem/qos_guest',method:'GET',params:{percent:'0.2',percent_up:'0.1'}});
  for(const d of [{download:501,upload:10},{download:100,upload:0},{download:'1;bad',upload:10}])assert.throws(()=>build('guestQos',d));
  assert.throws(()=>build('guestQos',{download:1,upload:1},{...context,'misystem/qos_info':{code:0,status:{on:0},band:{download:500,upload:100}}}));
  assert(!JSON.stringify(NETWORK_GROUPS).includes('qos_guest'));
  assert(!JSON.stringify(NETWORK_GROUPS).includes('scan_mesh_node'));
  assert.equal(build('channelScan',{}).steps[0].path,'xqnetwork/channel_scan_start');
});
test('Mesh bindings require the queried client, known supported node and preserve panel access',()=>{
  assert.deepEqual(build('meshBind',{mac:client,node,band:'5G'}).steps[0].params,{stamac:client,bindNode:'Living room',bindMac:node,bindBand:'5G'});
  assert.throws(()=>build('meshBind',{mac:self,node,band:'5G'}));
  assert.throws(()=>build('meshBind',{mac:client,node,band:'5G'},{...context,meshBindingMac:self}));
  assert.throws(()=>build('meshBind',{mac:client,node:'02:00:00:00:00:99',band:'5G'}));
  assert.throws(()=>build('meshBind',{mac:client,node,band:'6G'}));
  assert.deepEqual(build('meshBind',{mac:client,node:'none',band:'none'}).steps[0].params,{stamac:client,bindNode:'none',bindMac:'none',bindBand:'none'});
});
test('Adding Mesh accepts only a fresh server-captured discovery and safe location',()=>{
  assert.deepEqual(build('meshAdd',{mac:node,location:'Kitchen'}).steps[0].params,{mac:node,locate:'Kitchen'});
  assert.throws(()=>build('meshAdd',{mac:client,location:'Kitchen'}));
  assert.throws(()=>build('meshAdd',{mac:node,location:'Kitchen'},{...context,meshDiscovery:{...context.meshDiscovery,at:Date.now()-120001}}));
  assert.throws(()=>build('meshAdd',{mac:node,location:'Kitchen'},{...context,'misystem/child_mesh_infos':{code:0,childMeshInfos:[{lan_mac:node}]}}));
  assert.throws(()=>build('meshAdd',{mac:node,location:'a\nb'}));
});
test('Parental app edits validate minute quotas, preserve omissions and require known apps',()=>{
  const plan=build('parentalApps',{user_id:1,class_name:'games',on:1,apps:[{name:'Game',on:0}]});
  const op=JSON.parse(plan.steps[0].params.opt_list)[0];
  assert.deepEqual(op,{opt:'mipctl_set_app_antiaddict',user_id:1,list:[{class_name:'games',enable:true,app_list:[{name:'Game',enable:false}]}]});
  assert(!JSON.stringify(op).includes('time_quota'));
  const quota=JSON.parse(build('parentalApps',{user_id:1,class_name:'games',on:1,quotaMinutes:45}).steps[0].params.opt_list)[0];
  assert.equal(quota.list[0].time_quota,45);
  assert.equal(JSON.parse(build('parentalApps',{user_id:1,class_name:'games',on:1,quotaMinutes:0}).steps[0].params.opt_list)[0].list[0].time_quota,0);
  for(const quotaMinutes of [-1,1441,1.5,'45;bad'])assert.throws(()=>build('parentalApps',{user_id:1,class_name:'games',on:1,quotaMinutes}));
  for(const d of [{user_id:99,class_name:'games',on:1},{user_id:1,class_name:'unknown',on:1},{user_id:1,class_name:'games',on:1,quota:30},{user_id:1,class_name:'games',on:1,apps:[{name:'Unknown',on:1}]},{user_id:1,class_name:'games',on:1,apps:[{name:'Game',on:1},{name:'Game',on:0}]}])assert.throws(()=>build('parentalApps',d));
  assert.equal(JSON.parse(build('parentalAllow',{user_id:1,on:0}).steps[0].params.opt_list)[0].allow,false);
  assert.throws(()=>build('parentalAllow',{user_id:1,on:1},{...context,'misystem/feature_info':{apps:{}}}));
  assert.equal(build('unrelated',null),null);
});
