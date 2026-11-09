import test from 'node:test';
import assert from 'node:assert/strict';
import {buildSecurityPlan,logQuery} from '../security-plans.mjs';
import {fixture} from './fixture.mjs';
const self='02:00:00:00:00:01',peer='02:00:00:00:00:02',other='02:00:00:00:00:03';
test('IoT rules use JSON-array form fields and preserve the panel and topology nodes',()=>{
 const p=buildSecurityPlan('iotDevice',{mac:peer,on:1},fixture);
 assert.deepEqual(p.steps,[{path:'device_security/add_device',params:{mac:JSON.stringify([peer])},method:'POST'}]);
 assert.throws(()=>buildSecurityPlan('iotDevice',{mac:self,on:1},fixture));
 assert.throws(()=>buildSecurityPlan('iotGlobalTrusted',{macs:self,on:0},fixture));
 assert.throws(()=>buildSecurityPlan('iotDevice',{mac:'02:99:00:00:00:01',on:1},fixture));
 const nodeContext={...fixture,'misystem/topo_graph':{graph:{mac:peer}}};
 assert.throws(()=>buildSecurityPlan('iotDevice',{mac:peer,on:1},nodeContext));
 assert.throws(()=>buildSecurityPlan('iotTrusted',{mac:peer,peers:self,on:0},fixture));
 assert.equal(buildSecurityPlan('iotMark',{mac:peer,peers:other},fixture).steps[0].path,'device_security/mark_untrusted');
 assert.throws(()=>buildSecurityPlan('iotMark',{mac:peer,peers:'02:00:00:00:00:04'},fixture));
});
test('URL policy uses existing categories and whitelist adds require native authorization plus readback',()=>{
 const p=buildSecurityPlan('urlPolicy',{tag:'virus_download',policy:'alarm'},fixture);
 assert.deepEqual(p.steps[0].params,{tag:'virus_download',policy:'alarm'});
 assert.throws(()=>buildSecurityPlan('urlPolicy',{tag:'unknown',policy:'ignored'},fixture));
 assert.throws(()=>buildSecurityPlan('urlPolicy',{tag:'virus_download',policy:'allow'},fixture));
 assert.throws(()=>buildSecurityPlan('urlWhitelistAdd',{url:'example.net'},fixture));
 const ctx={...fixture,'panel/whitelistSession':{session:'fixture-authorization'}};
 const add=buildSecurityPlan('urlWhitelistAdd',{url:'EXAMPLE.net'},ctx);
 assert.deepEqual(add.checks,[{kind:'urlWhitelist',url:'example.net'}]);
 assert.throws(()=>buildSecurityPlan('urlWhitelistAdd',{url:'example.net;reboot'},ctx));
 assert.throws(()=>buildSecurityPlan('urlWhitelistDelete',{url:'example.net'},fixture));
});
test('Scanner config submits only advertised keys and logs enforce bounded pagination',()=>{
 const ctx={...fixture,'config_scanner/overview':{code:0,wifiKeyStrength:{enable_scan:1},UPnP:{enable_scan:1}}};
 const p=buildSecurityPlan('scanConfig',{enabled:['wifiKeyStrength']},ctx);
 assert.deepEqual(p.steps[0].params,{wifi_passwd_secure:'1',UPnP:'0'});
 assert.throws(()=>buildSecurityPlan('scanConfig',{enabled:['other']},ctx));
 assert.equal(logQuery({type:'risk',days:7,offset:0,limit:25}).limit,'25');
 assert.throws(()=>logQuery({type:'shell'}));assert.throws(()=>logQuery({type:'sys',limit:101}));
 assert.throws(()=>logQuery({type:'sys',offset:-1}));
 assert.equal(buildSecurityPlan('unrelated',{},ctx),null);
});
