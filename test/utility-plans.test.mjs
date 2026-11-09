import test from 'node:test';
import assert from 'node:assert/strict';
import {UTILITY_GROUPS,UTILITY_CONTEXT,buildUtilityPlan} from '../utility-plans.mjs';
const context=()=>({'xqnetwork/get_wps_info':{code:0,wps_enable:1,wpa3_only:0},'xqnetwork/wifi_detail_all':{code:0,info:[{status:'1',encryption:'psk2+ccmp'}]},'xqnetwork/wan_info':{code:0,info:{link:1,status:1}}});
test('WPS uses exact native fields and explicit admission confirmation',()=>{
  const current=context();assert.deepEqual(buildUtilityPlan('wpsEnable',{on:0},current).steps,[{path:'xqsystem/set_wps_enable',method:'POST',params:{enable:'0'}}]);
  assert.throws(()=>buildUtilityPlan('wpsStart',{},current));assert.throws(()=>buildUtilityPlan('wpsStart',{confirm:'yes'},current));
  const plan=buildUtilityPlan('wpsStart',{confirm:'ОТКРЫТЬ WPS'},current);assert.deepEqual(plan.steps,[{path:'xqsystem/wps',method:'GET',params:{}}]);assert(plan.notice.includes('без ввода'));
  current['xqnetwork/get_wps_info'].wps_enable=0;assert.throws(()=>buildUtilityPlan('wpsStart',{confirm:'ОТКРЫТЬ WPS'},current));
  current['xqnetwork/get_wps_info'].wpa3_only=1;assert.throws(()=>buildUtilityPlan('wpsEnable',{on:1},current));
  assert.equal(buildUtilityPlan('wpsCancel',{},current).steps[0].path,'xqsystem/wps_cancel');
  current['xqnetwork/get_wps_info'].wps_enable=undefined;assert.throws(()=>buildUtilityPlan('wpsCancel',{},current));
});
test('WPS excludes incompatible or disabled radios; speed result reads never start a test',()=>{
  const current=context();for(const radio of [{status:'1',encryption:'ccmp'},{status:'0',encryption:'psk2'},{status:'1',encryption:'none'}]){
    current['xqnetwork/wifi_detail_all'].info=[radio];assert.throws(()=>buildUtilityPlan('wpsStart',{confirm:'ОТКРЫТЬ WPS'},current));
  }
  const plan=buildUtilityPlan('speedtestStart',{},current);assert.deepEqual(plan.steps,[{path:'misystem/speed_test',method:'GET',params:{}}]);assert(plan.notice.includes('всех клиентов'));
  current['xqnetwork/wan_info'].info.link=0;assert.throws(()=>buildUtilityPlan('speedtestStart',{},current));
  assert.equal(UTILITY_GROUPS.diagnostics.speedtest,'misystem/speed_test_result');assert(!Object.values(UTILITY_GROUPS.diagnostics).includes('misystem/speed_test'));
  assert(!UTILITY_CONTEXT.speedtestStart.includes('misystem/speed_test_result'));assert.equal(buildUtilityPlan('unknown',{}),null);assert.throws(()=>buildUtilityPlan('wpsCancel',null,current));
});
