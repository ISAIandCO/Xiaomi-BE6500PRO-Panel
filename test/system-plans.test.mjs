import test from 'node:test';
import assert from 'node:assert/strict';
import {buildSystemPlan,TIMEZONES,RESTORE_LABELS} from '../system-plans.mjs';
test('System settings use native parameter names and authoritative timezone pairs',()=>{
 assert.equal(TIMEZONES.length,113);
 const zone=TIMEZONES.find(x=>x.index==='2.75');assert(zone);
 assert.deepEqual(buildSystemPlan('timezone',{index:zone.index}).steps[0].params,{timezone:zone.tz,index:zone.index});
 assert.throws(()=>buildSystemPlan('timezone',{index:'999',timezone:'arbitrary'}));
 assert.deepEqual(buildSystemPlan('otaSettings',{on:1,plugins:0,hour:4}).steps[0].params,{auto:'1',plugin:'0',time:'4'});
 assert.deepEqual(buildSystemPlan('pushSettings',{on:1,quiet:0}).steps[0].params,{auth:'1',quiet:'0'});
 assert.equal(buildSystemPlan('unmapped',{}),null);
});
test('Destructive operations require exact confirmation and fresh captured vendor metadata',()=>{
 assert.throws(()=>buildSystemPlan('reboot',{confirm:'yes'}));
 assert.deepEqual(buildSystemPlan('reboot',{confirm:'ПЕРЕЗАПУСТИТЬ'}).steps[0],{path:'xqsystem/reboot',method:'GET',params:{client:'web'}});
 assert.equal(buildSystemPlan('factoryReset',{confirm:'СБРОСИТЬ RD08',storage:0}).reauth,true);
 const context={'panel/update':{at:Date.now(),info:{needUpdate:1,downloadUrl:'https://cdn.cnbj1.fds.api.mi-img.com/rom/rd08.bin',version:'1.1.124',fileSize:100000,hash:'a'.repeat(32)}}};
 assert.equal(buildSystemPlan('onlineUpgrade',{confirm:'ОБНОВИТЬ RD08'},context).steps[0].params.needpermission,'1');
 for(const url of ['https://mi-img.com.evil.test/x.bin','https://user:pass@miwifi.com/x.bin','http://miwifi.com/x.bin','invalid']){
  context['panel/update'].info.downloadUrl=url;assert.throws(()=>buildSystemPlan('onlineUpgrade',{confirm:'ОБНОВИТЬ RD08'},context));
 }
 context['panel/update'].at=Date.now()-600001;assert.throws(()=>buildSystemPlan('onlineUpgrade',{confirm:'ОБНОВИТЬ RD08'},context));
});
test('Native restore accepts only offered known groups, flash refuses a reported downgrade',()=>{
 const stage={at:Date.now(),kind:'restore',inspection:{sha256:'a'.repeat(64)},reply:{des:{keys:{mi_wifi_info:RESTORE_LABELS.mi_wifi_info}}}};
 const context={'panel/systemStaged':stage};
 const plan=buildSystemPlan('restoreApply',{confirm:'ВОССТАНОВИТЬ RD08',keys:['mi_wifi_info']},context);
 assert.deepEqual(plan.steps[0].params,{keys:'mi_wifi_info'});assert(plan.reauth);
 assert.throws(()=>buildSystemPlan('restoreApply',{confirm:'ВОССТАНОВИТЬ RD08',keys:['mi_access_info']},context));
 stage.kind='firmware';stage.reply={downgrade:1};
 assert.throws(()=>buildSystemPlan('firmwareFlash',{confirm:'ПРОШИТЬ RD08',reset:0},context));
 stage.reply.downgrade=0;assert.deepEqual(buildSystemPlan('firmwareFlash',{confirm:'ПРОШИТЬ RD08',reset:1},context).steps[0].params,{custom:'1',recovery:'1'});
});
