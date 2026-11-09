import {PanelError,text,integer,mac,flag,choice,namesafe} from './core.mjs';

export const NETWORK_GROUPS={
  wifi:{weakSignal:'xqnetwork/get_wifi_weak',legacyRoaming:'xqnetwork/get_roam_rssi_threshold',channelQuality:'xqnetwork/channel_scan_result'},
  mesh:{meshSwitch:'xqnetwork/get_mesh_switch'},
  ports:{multiwanInfo:'xqnetwork/get_multiwan_basic_info',multiwanDevices:'xqnetwork/get_multiwan_dev_list'},
  parental:{features:'misystem/feature_info'},
};
export const NETWORK_CONTEXT={
  weakWifi:['xqnetwork/get_wifi_weak','xqnetwork/wifi_detail_all'],
  meshSwitch:['xqnetwork/get_mesh_switch'],legacyRoaming:['xqnetwork/get_roam_rssi_threshold'],
  multiwanDevice:['misystem/get_ps_service?service=multiwan','xqnetwork/get_multiwan_dev_policies','misystem/devicelist'],
  multiwanWeight:['misystem/get_ps_service?service=multiwan'],
  wanLink:['xqnetwork/wan_info'],pppoeLink:['xqnetwork/wan_info','misystem/get_ps_service?service=multiwan'],
  guestQos:['misystem/qos_info'],channelScan:['xqnetwork/wifi_detail_all'],
  meshBind:['misystem/devicelist','xqsystem/device_mac'],meshAdd:['misystem/child_mesh_infos'],
  meshDiscover:['misystem/get_mesh_bh_mode'],
  parentalApps:['misystem/mipctl_get_user_list'],parentalAllow:['misystem/mipctl_get_user_list','misystem/feature_info'],
};
const fail=message=>{throw new PanelError(message);};
function read(context,path){
  const value=context[path];
  if(!value||value.error||(value.code!==undefined&&+value.code!==0))fail('Не удалось прочитать актуальные параметры. Обновите раздел.');
  return value;
}
function amount(value,label){
  if(!['number','string'].includes(typeof value)||!/^\d+(?:\.\d+)?$/.test(String(value))||!Number.isFinite(+value)||+value<=0||+value>10000)fail(`«${label}»: введите скорость больше 0 и не выше 10000 Мбит/с.`);
  return +value;
}
const clientList=context=>read(context,'misystem/devicelist').list||[];
function dualWan(context){
  const value=read(context,'misystem/get_ps_service?service=multiwan').multiwan;
  if(!value||+value.enable!==1||!value.port_map?.some(p=>p.name==='WAN2'&&['1','2','3','4'].includes(String(p.port))))fail('Сначала настройте и включите второй WAN.');
  return value;
}

export function buildNetworkPlan(action,data,context={}){
  if(!Object.hasOwn(NETWORK_CONTEXT,action))return null;
  if(!data||typeof data!=='object'||Array.isArray(data))fail('Некорректная форма.');
  const steps=[],changes=[];let notice='',wait=0;
  const step=(path,params={},method='POST')=>steps.push({path,method,params});
  const change=(label,value)=>changes.push({label,value:String(value)});
  if(action==='weakWifi'){
    const index=integer(data.index,1,2,'Диапазон'),on=flag(data.on);
    const radio=read(context,'xqnetwork/wifi_detail_all').info?.[+index-1];
    const current=read(context,'xqnetwork/get_wifi_weak').info?.[+index-1];
    if(!radio||!current)fail('Диапазон отсутствует в актуальных настройках.');
    const bounds=index==='1'?[-95,-65,-100,-70]:[-85,-55,-90,-60];
    const weak=integer(data.weak,bounds[0],bounds[1],'Порог отказа, dBm'),kick=integer(data.kick,bounds[2],bounds[3],'Порог отключения, dBm');
    if(+kick>+weak)fail('Порог отключения должен быть не выше порога отказа.');
    step('xqnetwork/set_wifi_weak',{wifiIndex:index,weakenable:on,weakthreshold:weak,kickthreshold:kick});
    change('Слабые клиенты '+(index==='1'?'2,4':'5')+' ГГц',on==='1'?`Включить: отказ ${weak} dBm, отключение ${kick} dBm`:'Выключить');
    notice='Радиомодули перезапустятся. Клиенты со слабым сигналом могут потерять связь.';wait=30;
  }else if(action==='meshSwitch'){
    const current=read(context,'xqnetwork/get_mesh_switch').enabled;
    if(!['0','1'].includes(String(current)))fail('Роутер уже работает в специальном режиме Mesh; этот переключатель в нём не применяется.');
    const on=flag(data.on);step('xqnetwork/set_mesh_switch',{on});change('Обнаружение Mesh',on==='1'?'Включить':'Выключить');
    notice='Меняется работа Mesh. Узлы могут временно потерять связь.';wait=15;
  }else if(action==='legacyRoaming'){
    const current=read(context,'xqnetwork/get_roam_rssi_threshold');
    if(current.RoamRssiThreshold2G===undefined||current.RoamRssiThreshold5G===undefined)fail('Пороги прежнего механизма роуминга недоступны.');
    const rssi2g=integer(data.rssi2g,-95,-50,'Порог 2,4 ГГц'),rssi5g=integer(data.rssi5g,-95,-50,'Порог 5 ГГц');
    step('xqnetwork/set_roam_rssi_threshold',{roamrssithreshold1:rssi2g,roamrssithreshold2:rssi5g});change('Прежний механизм роуминга',`${rssi2g} / ${rssi5g} dBm`);
    notice='Изменяются отдельные пороги старого механизма steering. Это не настройка современного ручного роуминга. Служба Mesh перезапустится.';wait=15;
  }else if(action==='multiwanDevice'){
    dualWan(context);
    const address=mac(data.mac),on=flag(data.on),policies=read(context,'xqnetwork/get_multiwan_dev_policies').info?.dev_policies;
    if(!Array.isArray(policies))fail('Не удалось прочитать правила Dual WAN.');
    const old=policies.find(p=>String(p.mac).toUpperCase()===address),device=clientList(context).find(p=>String(p.mac).toUpperCase()===address);
    if(on==='0'&&!old)fail('Правило больше не существует.');
    const manual=flag(data.manual??old?.manual??(device?0:1));
    if(manual==='0'&&!device&&on==='1')fail('Устройство отсутствует в актуальном списке.');
    const wan=choice(data.wan??old?.wan,['WAN1','WAN2'],'WAN'),name=namesafe(data.name||old?.oname||device?.oname||device?.name||address);
    step('xqnetwork/set_multiwan_dev_policy',{mac:address,manual,wan,oname:name,opt:on==='1'?'0':'1'});
    change('Правило Dual WAN',on==='1'?`${name} → ${wan}`:`Удалить ${name}`);notice='Изменится выход в Интернет выбранного устройства. Текущие соединения могут оборваться.';wait=10;
  }else if(action==='multiwanWeight'){
    dualWan(context);const wan1=amount(data.wan1,'WAN1'),wan2=amount(data.wan2,'WAN2');
    if(Math.max(wan1,wan2)/Math.min(wan1,wan2)>100)fail('Отношение скоростей WAN должно быть не больше 100:1.');
    step('xqnetwork/set_multiwan_weight',{bandwidth_wan1:String(wan1),bandwidth_wan2:String(wan2)});change('Полоса Dual WAN',`${wan1} / ${wan2} Мбит/с`);
    notice='Изменятся веса распределения соединений. Служба Dual WAN перезапустится.';wait=15;
  }else if(action==='wanLink'){
    if(!read(context,'xqnetwork/wan_info').info)fail('Не удалось прочитать WAN1.');
    const on=flag(data.on);step('xqnetwork/wan_'+(on==='1'?'up':'down'),{},'GET');change('WAN1',on==='1'?'Подключить':'Отключить');notice='Интернет всех устройств через WAN1 может прерваться.';wait=15;
  }else if(action==='pppoeLink'){
    const wan=choice(data.wan,['WAN1','WAN2'],'WAN'),on=flag(data.on);
    if(wan==='WAN2')dualWan(context);
    const current=read(context,wan==='WAN1'?'xqnetwork/wan_info':'xqnetwork/wan_info:WAN2');
    if(String(current.info?.details?.wanType).toLowerCase()!=='pppoe')fail('Для выбранного WAN не настроен PPPoE.');
    step('xqnetwork/pppoe_'+(on==='1'?'start':'stop'),{wan_name:wan},'GET');change('PPPoE '+wan,on==='1'?'Подключить':'Отключить');notice='Соединение провайдера и текущие подключения через этот WAN могут прерваться.';wait=15;
  }else if(action==='guestQos'){
    const qos=read(context,'misystem/qos_info');if(+qos.status?.on!==1)fail('Сначала включите QoS и задайте скорость тарифа.');
    const download=amount(data.download,'Загрузка гостей'),upload=amount(data.upload,'Отдача гостей');
    const downBand=amount(qos.band?.download,'Скорость тарифа: загрузка'),upBand=amount(qos.band?.upload,'Скорость тарифа: отдача');
    if(download>downBand||upload>upBand)fail('Гостевой лимит не должен превышать скорость тарифа.');
    step('misystem/qos_guest',{percent:String(download/downBand),percent_up:String(upload/upBand)},'GET');change('Полоса гостей',`${download} / ${upload} Мбит/с`);notice='Меняется общая полоса гостевой сети. При изменении скорости тарифа фактические лимиты нужно проверить снова.';
  }else if(action==='channelScan'){
    if(String(read(context,'xqnetwork/wifi_detail_all').info?.[0]?.status)!=='1')fail('Сначала включите радиомодуль 2,4 ГГц.');
    step('xqnetwork/channel_scan_start',{},'GET');change('Качество каналов','Запустить измерение 2,4 ГГц');notice='Во время измерения качество Wi-Fi может временно снизиться. Этот диагностический механизм оценивает только 2,4 ГГц.';wait=8;
  }else if(action==='meshBind'){
    const address=mac(data.mac),nodeMac=data.node==='none'?'none':mac(data.node),band=choice(data.band,['none','2G','5G'],'Диапазон');
    if(!clientList(context).some(p=>String(p.mac).toUpperCase()===address))fail('Клиент отсутствует в актуальном списке.');
    const self=read(context,'xqsystem/device_mac').mac;if(!self)fail('Не удалось определить компьютер панели.');
    if(address===String(self).toUpperCase()&&(nodeMac!=='none'||band!=='none'))fail('Нельзя ограничивать узел или диапазон компьютера панели.');
    // The server must annotate the parameterized read with the client it actually queried.
    if(String(context.meshBindingMac).toUpperCase()!==address)fail('Сначала прочитайте привязку выбранного клиента.');
    const binding=read(context,'xqnetwork/get_sta_bindinfo');
    if(!binding.bindinfo||!Array.isArray(binding.meshnode))fail('Не удалось получить доступные узлы Mesh.');
    const node=nodeMac==='none'?null:binding.meshnode.find(n=>String(n.mac).toUpperCase()===nodeMac);
    if(nodeMac!=='none'&&(!node||+node.support_accessCtl!==1||+node.wifiup!==1))fail('Выбранный узел недоступен или не поддерживает привязку.');
    const name=node?text(node.router_name||node.location||nodeMac,'Узел Mesh',128):'none';
    step('xqnetwork/set_sta_bindinfo',{stamac:address,bindNode:name,bindMac:nodeMac,bindBand:band});change('Привязка клиента',`${address} → ${node?name:'любой узел'}, ${band==='none'?'любой диапазон':band}`);
    notice='Роутер может немедленно отключить клиента от текущего Wi-Fi. Выбранный узел и диапазон должны находиться в зоне приёма.';wait=15;
  }else if(action==='meshDiscover'){
    read(context,'misystem/get_mesh_bh_mode');step('xqnetwork/scan_mesh_node',{},'GET');change('Поиск Mesh','Найти роутеры, готовые к подключению');
    notice='Поиск может включить служебную точку доступа backhaul и обновить обнаружение узлов. Добавление найденного роутера выполняется отдельным действием.';
  }else if(action==='meshAdd'){
    const address=mac(data.mac),scan=context.meshDiscovery;
    if(!scan||!Number.isFinite(scan.at)||scan.at>Date.now()+1000||Date.now()-scan.at>120000||scan.result?.code!==0||!scan.result.list?.some(n=>String(n.mac).toUpperCase()===address))fail('Узел отсутствует в свежем результате поиска. Выполните поиск снова.');
    const children=read(context,'misystem/child_mesh_infos').childMeshInfos||[];
    if(children.some(n=>[n.mac,n.lan_mac,n.lanMac].some(m=>String(m).toUpperCase()===address)))fail('Этот узел уже добавлен.');
    const locate=namesafe(data.location);step('xqnetwork/add_mesh_node',{mac:address,locate});change('Добавить узел Mesh',`${address} · ${locate}`);notice='Меняется топология сети. Добавляемый роутер должен поддерживать Xiaomi Mesh и находиться в режиме ожидания подключения.';wait=30;
  }else{
    const userId=+integer(data.user_id,1,2147483647,'Профиль');
    if(!read(context,'misystem/mipctl_get_user_list').user_list?.some(u=>+u.user_id===userId))fail('Профиль больше не существует.');
    let op;
    if(action==='parentalAllow'){
      if(String(read(context,'misystem/feature_info').apps?.mipctlv2_temp_allow)!=='1')fail('Временное разрешение не поддерживается этой конфигурацией.');
      read(context,'misystem/mipctl_get_temp_allow');
      op={opt:'mipctl_set_temp_allow',user_id:userId,allow:flag(data.on)==='1'};change('Временный доступ',op.allow?'Разрешить до следующего периода':'Отменить временное разрешение');
    }else{
      if(Object.hasOwn(data,'quota')||Object.hasOwn(data,'time_quota'))fail('Квота задаётся только полем «Минут в день».');
      const list=read(context,'misystem/mipctl_get_app_antiaddict').list;
      const name=text(data.class_name,'Категория',128),entry=Array.isArray(list)&&list.find(c=>c.class_name===name);
      if(!entry||!Array.isArray(entry.app_list))fail('Категория отсутствует в актуальной базе приложений.');
      const edit={class_name:name,enable:flag(data.on)==='1'};
      if(data.quotaMinutes!==undefined)edit.time_quota=+integer(data.quotaMinutes,0,1440,'Минут в день');
      if(data.apps!==undefined){
        if(!Array.isArray(data.apps)||data.apps.length>entry.app_list.length)fail('Некорректный список приложений.');
        const seen=new Set();edit.app_list=data.apps.map(a=>{
          if(!a||typeof a!=='object'||seen.has(a.name)||!entry.app_list.some(x=>x.name===a.name))fail('Приложение отсутствует в актуальной категории или повторяется.');
          seen.add(a.name);return{name:a.name,enable:flag(a.on)==='1'};
        });
      }
      op={opt:'mipctl_set_app_antiaddict',user_id:userId,list:[edit]};change('Категория приложений',`${name}: ${edit.enable?'включить ограничения':'выключить ограничения'}`);change('Квота времени',edit.time_quota===undefined?'Сохранить текущее значение':`${edit.time_quota} минут в день`);
      if(edit.app_list)change('Приложения',edit.app_list.map(a=>`${a.name}: ${a.enable?'учитывать':'не учитывать'}`).join(', ')||'Сохранить текущий список');
    }
    step('misystem/mipctl_set',{opt_list:JSON.stringify([op])});notice='Меняются ограничения выбранного профиля. Остальные категории сохраняются; правила действуют на устройства профиля.';
  }
  return{steps,changes,notice,wait};
}
