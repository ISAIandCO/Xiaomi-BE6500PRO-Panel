import {PanelError,flag} from './core.mjs';

export const UTILITY_GROUPS={security:{wpsStatus:'xqsystem/wps_status'},diagnostics:{speedtest:'misystem/speed_test_result'}};
export const UTILITY_CONTEXT={
  wpsEnable:['xqnetwork/get_wps_info'],wpsStart:['xqnetwork/get_wps_info','xqnetwork/wifi_detail_all'],
  wpsCancel:['xqnetwork/get_wps_info'],speedtestStart:['xqnetwork/wan_info'],
};
const fail=message=>{throw new PanelError(message);};
function read(context,path){
  const value=context[path];
  if(!value||value.error||(value.code!==undefined&&+value.code!==0))fail('Не удалось прочитать актуальные параметры. Обновите раздел.');
  return value;
}
function wps(context){
  const value=read(context,'xqnetwork/get_wps_info');
  if(!['0','1'].includes(String(value.wps_enable))||!['0','1'].includes(String(value.wpa3_only)))fail('Роутер не сообщил поддерживаемое состояние WPS.');
  return value;
}
export function buildUtilityPlan(action,data,context={}){
  if(!Object.hasOwn(UTILITY_CONTEXT,action))return null;
  if(!data||typeof data!=='object'||Array.isArray(data))fail('Некорректная форма.');
  const steps=[],changes=[];let notice='',wait=0;
  const step=(path,params={},method='GET')=>steps.push({path,method,params});
  const change=(label,value)=>changes.push({label,value:String(value)});
  if(action==='wpsEnable'){
    const state=wps(context),on=flag(data.on);
    if(on==='1'&&String(state.wpa3_only)==='1')fail('Текущая сеть использует только WPA3; штатный WPS для неё недоступен.');
    step('xqsystem/set_wps_enable',{enable:on},'POST');change('WPS',on==='1'?'Разрешить':'Запретить');
    notice='Меняется штатное разрешение WPS. Окно подключения открывается отдельной командой; выключение флага не заменяет отмену уже запущенного подключения.';
  }else if(action==='wpsStart'){
    const state=wps(context);
    if(data.confirm!=='ОТКРЫТЬ WPS')fail('Для запуска введите ОТКРЫТЬ WPS.');
    if(String(state.wps_enable)!=='1'||String(state.wpa3_only)!=='0')fail('Сначала разрешите WPS в совместимой сети WPA2 / WPA3.');
    const radios=read(context,'xqnetwork/wifi_detail_all').info;
    if(!Array.isArray(radios)||!radios.some(r=>String(r.status)==='1'&&['psk2','mixed-psk','psk2+ccmp'].includes(r.encryption)))fail('Нет включённой основной сети с подтверждённой поддержкой WPS.');
    step('xqsystem/wps');change('WPS PBC','Открыть окно подключения новых устройств без ввода пароля');
    notice='В период WPS находящиеся рядом совместимые устройства могут подключиться к сети без ввода её пароля. Нажмите WPS на своём устройстве. Окно можно закрыть отдельной отменой.';wait=2;
  }else if(action==='wpsCancel'){
    wps(context);step('xqsystem/wps_cancel');change('WPS PBC','Остановить ожидание подключения');
    notice='Ожидание новых подключений WPS будет остановлено. Уже подключённые устройства сохранят доступ к сети.';wait=2;
  }else if(action==='speedtestStart'){
    const wan=read(context,'xqnetwork/wan_info').info;
    if(!wan||String(wan.link)!=='1'||String(wan.status)!=='1')fail('Сначала восстановите подключение WAN.');
    step('misystem/speed_test');change('Штатный тест скорости','Измерить отправку и загрузку через WAN');
    notice='Тест создаёт интенсивный внешний трафик и может занять WAN, замедлив Интернет для всех клиентов. Он обращается к штатным серверам измерения и перезаписывает последний результат роутера. После запуска обновите раздел для чтения результата.';wait=15;
  }
  return {steps,changes,notice,wait};
}
