import test from 'node:test';
import assert from 'node:assert/strict';
import {renderWps,renderSpeedtest} from '../public/utilities-ui.js';
function helpers(){
  const forms=[],el=(tag,attrs={},...children)=>({tag,attrs,children:children.flat(Infinity).filter(x=>x!=null)}),wrap=tag=>(...children)=>el(tag,{},children);
  return {forms,el,card:wrap('card'),note:wrap('note'),facts:wrap('facts'),fact:wrap('fact'),details:wrap('details'),raw:wrap('raw'),
    fields:(name,label,value,type,options,extra)=>({name,label,value,type,options,...extra}),
    formCard:(title,description,specs,action)=>{forms.push({title,description,specs,action});return el('form',{},title,description);}};
}
function strings(node){if(node==null)return [];return typeof node==='object'?(node.children||[]).flatMap(strings):[String(node)];}
test('WPS requires typed confirmation and tolerates invalid native timestamps',()=>{
  const h=helpers();renderWps({wps:{code:0,wps_enable:1,wpa3_only:0},wpsStatus:{code:0,status:1,startTime:'not-an-epoch',currentTime:'1794160000'}},h);
  assert.deepEqual(h.forms.map(x=>x.action),['wpsEnable','wpsStart','wpsCancel']);assert.equal(h.forms[1].specs[0].name,'confirm');assert(h.forms[1].specs[0].label.includes('ОТКРЫТЬ WPS'));
  const restricted=helpers();renderWps({wps:{code:0,wps_enable:1,wpa3_only:1}},restricted);assert(!restricted.forms.some(x=>x.action==='wpsStart'));
});
test('Speed UI converts native KiB/s, treats missing results honestly and never starts by rendering',()=>{
  const h=helpers(),root=renderSpeedtest({speedtest:{code:0,status:2,up:1024,down:'12207.03125'}},h),text=strings(root).join(' ');
  assert(text.includes('8,39 Мбит/с'));assert(text.includes('100 Мбит/с'));assert.equal(h.forms[0].action,'speedtestStart');
  for(const result of [{code:1588},{code:0,status:1},{code:0,status:2,up:'Infinity',down:-1}])assert(!strings(renderSpeedtest({speedtest:result},helpers())).some(x=>x.endsWith('Мбит/с')));
});
