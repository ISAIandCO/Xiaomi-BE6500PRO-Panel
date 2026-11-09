import test from 'node:test';
import assert from 'node:assert/strict';
import {renderSystemExtras,renderSystemStage,renderUpdate} from '../public/system-ui.js';

function helpers() {
  const forms=[];
  const el=(tag,attrs={},...children)=>({tag,attrs,children:children.flat(Infinity).filter(x=>x!=null),append(...values){this.children.push(...values);}});
  const wrap=tag=>(...children)=>el(tag,{},children);
  return {forms,el,grid:(_, ...children)=>el('grid',{},children),note:wrap('note'),card:wrap('card'),facts:wrap('facts'),fact:wrap('fact'),details:wrap('details'),raw:wrap('raw'),
    fields:(name,label,value,type='text',options=[],extra={})=>({name,label,value,type,options,...extra}),
    formCard:(title,description,specs,action,transform=x=>x)=>{const form={title,description,specs,action,transform};forms.push(form);return el('form',{action},title);},
    info:{writeSupported:true},RESTORE_LABELS:{mi_wifi_info:'Wi-Fi',mi_lan_info:'LAN'},checkUpdate(){},inspectSystemFile(){},stageFile(){}};
}
function nodes(node){return typeof node==='object'&&node!==null?[node,...(node.children||[]).flatMap(nodes)]:[];}
function safe(node){for(const item of nodes(node))for(const key of Object.keys(item.attrs||{}))assert(!['innerHTML','outerHTML','style'].includes(key));}

test('System extras reuse form actions and safe DOM fields, with no automatic callbacks',()=>{
  const h=helpers(),malicious='<img src=x onerror=alert(1)>',timezones=[{index:'2.75',label:malicious}];
  h.checkUpdate=()=>assert.fail('No automatic update check');h.inspectSystemFile=()=>assert.fail('No automatic file upload');
  const root=renderSystemExtras({ota:{auto:1,plugin:0,time:4},privacy:{privacy:0},push:{auth:1,quiet:0},https:{on:1},time:{time:{index:'2.75'}}},timezones,h);
  assert.deepEqual(h.forms.map(x=>x.action),['otaSettings','timezone','privacyProgram','pushSettings','forceHttps','adminPassword','reboot','factoryReset']);
  assert.equal(h.forms.find(x=>x.action==='timezone').specs[0].options[0][1],malicious);
  assert.deepEqual(h.forms.find(x=>x.action==='adminPassword').specs.map(x=>[x.name,x.type,x.value]),[['oldPassword','password',''],['newPassword','password',''],['repeatPassword','password','']]);
  const ids=nodes(root).map(x=>x.attrs.id).filter(Boolean);for(const id of ['update-check','update-result','system-file-kind','system-file','system-file-check','system-stage'])assert(ids.includes(id));
  assert(h.forms.find(x=>x.action==='reboot').specs[0].label.includes('ПЕРЕЗАПУСТИТЬ'));safe(root);
});

test('Update and staged-file controls appear only for the matching native state',()=>{
  const h=helpers();safe(renderUpdate({needUpdate:0},h));assert.equal(h.forms.length,0);
  safe(renderUpdate({needUpdate:1,version:'<script>alert(1)</script>'},h));assert.equal(h.forms[0].action,'onlineUpgrade');
  h.forms.length=0;let sent;
  h.stageFile=(inspection,event)=>{sent={inspection,event};};
  const local=renderSystemStage({kind:'firmware',inspection:{valid:true,sha256:'a'.repeat(64)}},h);
  assert.equal(h.forms.length,0);const button=nodes(local).find(x=>x.tag==='button');button.attrs.onClick('event');assert.equal(sent.inspection.kind,'firmware');assert.equal(sent.event,'event');safe(local);
  const failed=renderSystemStage({kind:'firmware',inspection:{valid:false}},h);assert(!nodes(failed).some(x=>x.tag==='button'));
  renderSystemStage({kind:'firmware',inspection:{},reply:{downgrade:1}},h);assert.equal(h.forms.length,0);
  renderSystemStage({kind:'firmware',inspection:{},reply:{downgrade:0}},h);assert.equal(h.forms[0].action,'firmwareFlash');
  h.forms.length=0;const restored=renderSystemStage({kind:'restore',inspection:{},reply:{des:{keys:{mi_wifi_info:'Native label',mi_mobile_info:'Other model'}}}},h);
  assert.equal(h.forms[0].action,'restoreApply');assert.deepEqual(h.forms[0].specs[0].options,[['mi_wifi_info','Wi-Fi']]);assert.deepEqual(h.forms[0].specs[0].value,[]);safe(restored);
});
