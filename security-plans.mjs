import {PanelError,text,integer,mac,flag,choice} from './core.mjs';

const fail=message=>{throw new PanelError(message);};
export const SECURITY_GROUPS={
  iotSecurity:{devices:'misystem/devicelist',self:'xqsystem/device_mac',protection:'device_security/overview',trusted:'device_security/get_global_trusted',topology:'misystem/topo_graph'},
  securityEvents:{config:'mi_log/get_onoff',overview:'mi_log/overview'},
  scanner:{scanner:'config_scanner/overview'},
  security:{whitelist:'url_fw/show_whitelist'},
};
const iotContext=['misystem/devicelist','xqsystem/device_mac','device_security/overview','device_security/get_global_trusted','misystem/topo_graph'];
export const SECURITY_CONTEXT={
  iotFirewall:iotContext,iotDevice:iotContext,iotGlobalTrusted:iotContext,iotTrusted:iotContext,iotMark:iotContext,
  urlPolicy:['url_fw/show_policy'],urlWhitelistDelete:['url_fw/show_whitelist'],urlWhitelistAdd:['url_fw/show_whitelist'],
  scanConfig:['config_scanner/overview'],logSwitch:['mi_log/get_onoff'],logDelete:[],
};
const addresses=value=>{
  if(typeof value!=='string'||value.length>8192)fail('Некорректный список MAC-адресов.');
  const list=[...new Set(value.split(/[\s,;]+/).filter(Boolean).map(mac))];
  if(!list.length||list.length>128)fail('Укажите от 1 до 128 MAC-адресов.');return list;
};
const urlValue=value=>{
  const valueText=text(value,'Домен исключения',253).toLowerCase();
  if(!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(valueText)||valueText.includes('..'))fail('Укажите домен без протокола, пути и порта.');return valueText;
};
export function buildSecurityPlan(action,data,context={}){
  if(!Object.hasOwn(SECURITY_CONTEXT,action))return null;
  if(!data||typeof data!=='object'||Array.isArray(data))fail('Некорректная форма.');
  const steps=[],changes=[],checks=[];let notice='';
  const step=(path,params)=>steps.push({path,params,method:'POST'});
  const change=(label,value)=>changes.push({label,value:String(value)});
  const self=String(context['xqsystem/device_mac']?.mac||'').toUpperCase();
  const devices=context['misystem/devicelist']?.list||[];
  const known=value=>{const address=mac(value);if(!devices.some(d=>String(d.mac).toUpperCase()===address))fail('Устройства нет в текущем списке.');return address;};
  const protectedAddresses=new Set([self]);
  function protectNodes(value){if(!value||typeof value!=='object')return;for(const[k,v]of Object.entries(value)){if(/mac/i.test(k)&&typeof v==='string'&&/^[\da-f]{2}(?::[\da-f]{2}){5}$/i.test(v))protectedAddresses.add(v.toUpperCase());else if(typeof v==='object')protectNodes(v);}}
  protectNodes(context['misystem/topo_graph']);
  const trusted=context['device_security/get_global_trusted']?.meta?.trusted||[];
  if(action==='iotFirewall'){
    step('device_security/switch',{enable:flag(data.on)});change('Брандмауэр умных устройств',data.on==1?'Включить':'Выключить');
  }else if(action==='iotDevice'){
    const address=known(data.mac),on=flag(data.on);
    if(on==='1'&&protectedAddresses.has(address))fail('Нельзя ограничить компьютер панели или узел Mesh.');
    step('device_security/'+(on==='1'?'add_device':'del_device'),{mac:JSON.stringify([address])});change('Защита устройства',`${address}: ${on==='1'?'включить':'выключить'}`);
  }else if(action==='iotGlobalTrusted'){
    const list=addresses(data.macs),on=flag(data.on);
    if(on==='0'&&list.some(m=>protectedAddresses.has(m)))fail('Нельзя удалить компьютер панели или узлы Mesh из доверенных.');
    if(on==='0'&&list.some(m=>!trusted.some(t=>String(t).toUpperCase()===m)))fail('Одного из адресов больше нет в доверенном списке.');
    step('device_security/'+(on==='1'?'add_global_trusted':'del_global_trusted'),{mac:JSON.stringify(list)});change('Общие доверенные устройства',`${on==='1'?'Добавить':'Удалить'}: ${list.join(', ')}`);
  }else if(action==='iotTrusted'||action==='iotMark'){
    const source=known(data.mac),peers=addresses(data.peers);
    if(protectedAddresses.has(source))fail('Нельзя изменять ограничения компьютера панели или узла Mesh.');
    const on=action==='iotMark'?'0':flag(data.on),current=context['device_security/get_trusted']?.meta?.trusted||{},blocked=context['device_security/get_blocked']?.meta?.blocked||{};
    if(on==='0'&&peers.some(m=>protectedAddresses.has(m)))fail('Нельзя ограничить связь с компьютером панели или узлами Mesh.');
    if(action==='iotMark'&&peers.some(m=>!Object.hasOwn(blocked,m)))fail('Отметить можно только текущую заблокированную связь.');
    if(action==='iotTrusted'&&on==='0'&&peers.some(m=>!Object.hasOwn(current,m)))fail('Одного из адресов больше нет в доверенных связях.');
    step('device_security/'+(action==='iotMark'?'mark_untrusted':on==='1'?'add_trusted':'del_trusted'),{mac:source,[action==='iotMark'?'untrusted':'trusted']:JSON.stringify(peers)});change('Связи устройства',`${source}: ${peers.join(', ')}`);
  }else if(action==='urlPolicy'){
    const policy=choice(data.policy,['reject','alarm','log','ignored'],'Политика'),list=context['url_fw/show_policy']?.list||[];
    const category=list.find(p=>p.tag===data.tag);if(!category)fail('Категория больше не существует.');
    step('url_fw/update_policy',{tag:category.tag,policy});change('Категория фильтра',category.name||category.tag);change('Политика',({reject:'Блокировать',alarm:'Предупреждать',log:'Записывать',ignored:'Игнорировать'})[policy]);
  }else if(action==='urlWhitelistDelete'){
    const url=text(data.url,'Исключение',2048),current=context['url_fw/show_whitelist']?.whitelist||[];
    if(!current.some(x=>x.url===url))fail('Исключение больше не существует.');
    step('url_fw/del_whitelist',{url:JSON.stringify([url])});change('Удалить исключение фильтра',url);
  }else if(action==='urlWhitelistAdd'){
    const url=urlValue(data.url),session=context['panel/whitelistSession']?.session;
    if(typeof session!=='string'||!session||session==='0')fail('Роутер не выдал разрешение на исключение этого домена.');
    step('url_fw/add_whitelist',{url,session});checks.push({kind:'urlWhitelist',url});change('Добавить исключение фильтра',url);
  }else if(action==='scanConfig'){
    const current=context['config_scanner/overview']||{},params={};
    if(!Array.isArray(data.enabled))fail('Некорректный список проверок.');
    const knownChecks=Object.entries(current).filter(([,v])=>v&&typeof v==='object'&&Object.hasOwn(v,'enable_scan')).map(([k])=>k);
    if(!knownChecks.length||data.enabled.some(k=>!knownChecks.includes(k)))fail('Список проверок изменился. Обновите страницу.');
    for(const key of knownChecks)params[key==='wifiKeyStrength'?'wifi_passwd_secure':key]=data.enabled.includes(key)?'1':'0';
    step('config_scanner/config',params);change('Проверки конфигурации',`${data.enabled.length} из ${knownChecks.length}`);
  }else if(action==='logSwitch'){
    step('mi_log/set_onoff',{on:flag(data.on)});change('Журнал безопасности',data.on==1?'Включить':'Выключить');
  }else if(action==='logDelete'){
    const page=context['panel/logPage'];
    if(!Array.isArray(data.ids)||!data.ids.length||data.ids.length>100||!page)fail('Сначала загрузите нужную страницу журнала.');
    const ids=[...new Set(data.ids.map(id=>integer(id,1,Number.MAX_SAFE_INTEGER,'Запись журнала')))];
    if(ids.some(id=>!page.ids.includes(id)))fail('Можно удалить только записи последней загруженной страницы.');
    step('mi_log/del_logs',{type:'ids',value:JSON.stringify(ids.map(Number)),filter:page.params.type});change('Удалить записи журнала',ids.join(', '));
    notice='Выбранные записи будут удалены без возможности восстановления. Остальные записи сохраняются.';
  }
  if(action.startsWith('iot'))notice='Меняются связи внутри локальной сети. Устройства IoT могут потерять связь с другими клиентами; доверенные исключения действуют отдельно.';
  return {steps,changes,checks,notice,wait:0};
}

export const securityDomain=urlValue;
export function logQuery(data){
  return {type:choice(data.type,['risk','sys','nic'],'Раздел журнала'),tsclient:integer(data.tsclient??Math.floor(Date.now()/1000),1,4102444800,'Время'),duration:integer(data.days??7,1,365,'Период, дней'),offset:integer(data.offset??0,0,100000,'Смещение'),limit:integer(data.limit??25,1,100,'Размер страницы')};
}
