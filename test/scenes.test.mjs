import test from 'node:test';
import assert from 'node:assert/strict';
import {buildPlan,READ_PARAMS} from '../core.mjs';
import {fixture} from './fixture.mjs';
const context={...fixture,'misystem/sys_time':{code:0,time:{timezone:'<+05>-5'}}};
const data={name:'Перезапуск',kind:'normal_reboot',time:'04:00',days:['5','1','3'],on:0};
const command=plan=>JSON.parse(plan.steps[0].params.payload);
test('Scene writes use fixed built-in actions and never execute immediately',()=>{
 assert.deepEqual(JSON.parse(READ_PARAMS['xqsmarthome/request_smartcontroller'].payload),{command:'get_scene_setting'});
 const c=command(buildPlan('sceneSave',data,context));
 assert.equal(c.command,'scene_setting');assert.equal(c.id,30010);assert.equal(c.launch.timer.repeat,'1,3,5');assert.equal(c.launch.timer.enabled,false);
 assert.equal(c.action_list[0].type,'normal_reboot');assert.deepEqual(c.action_list[0].payload,{});
 assert.throws(()=>buildPlan('sceneSave',{...data,kind:'system'},context));
 assert.throws(()=>buildPlan('sceneSave',{...data,time:'24:00'},context));
 assert.throws(()=>buildPlan('sceneSave',{...data,days:['7']},context));
 assert.throws(()=>buildPlan('sceneSave',{...data,name:'x;reboot'},context));
});
test('Updating and toggling scenes requires a current supported timer',()=>{
 const old=fixture['xqsmarthome/request_smartcontroller'].scene_list[0];
 const toggle=command(buildPlan('sceneToggle',{id:old.id,on:0},context));
 assert.equal(toggle.command,'scene_update');assert.deepEqual(toggle.action_list,old.action_list);assert.equal(toggle.launch.timer.enabled,false);
 assert.deepEqual(command(buildPlan('sceneDelete',{id:old.id},context)),{command:'scene_delete',id:old.id});
 assert.throws(()=>buildPlan('sceneDelete',{id:99},context));
 const complex={...context,'xqsmarthome/request_smartcontroller':{code:0,scene_list:[{...old,action_list:[...old.action_list,{type:'miio'}]}]}};
 assert.throws(()=>buildPlan('sceneToggle',{id:old.id,on:1},complex));
});
test('One-shot timestamps use the router POSIX timezone and reject invalid dates',()=>{
 const c=command(buildPlan('sceneSave',{...data,days:[],date:'2099-01-02'},context));
 assert.equal(c.launch.timer.utc_time,Date.parse('2099-01-01T23:00:00Z'));
 assert.throws(()=>buildPlan('sceneSave',{...data,days:[],date:'2099-02-30'},context));
 assert.throws(()=>buildPlan('sceneSave',{...data,days:[],date:'2000-01-01'},context));
 const dst={...context,'misystem/sys_time':{code:0,time:{timezone:'CET-1CEST,M3.5.0,M10.5.0/3'}}};
 assert.throws(()=>buildPlan('sceneSave',{...data,days:[],date:'2099-01-02'},dst));
});
test('Wi-Fi schedules bound the restore duration and allocate a separate nonconflicting ID',()=>{
 const c=command(buildPlan('sceneSave',{...data,kind:'normal_wifi_down',minutes:480},context));
 assert.equal(c.id,40000);assert.equal(c.action_list[0].extra.duration,28800000);
 assert.throws(()=>buildPlan('sceneSave',{...data,kind:'guest_wifi_down',minutes:0},context));
});
