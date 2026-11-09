import {readFileSync} from 'node:fs';
import {PanelError,text,integer,flag,mac} from './core.mjs';

export const TIMEZONES=JSON.parse(readFileSync(new URL('./timezones.json',import.meta.url),'utf8'));
export const SYSTEM_GROUPS={system:{ota:'misystem/ota',privacy:'xqsystem/privacy',push:'xqsystem/push_settings',https:'xqsystem/get_access_force_https',features:'misystem/feature_info',upgrade:'xqsystem/upgrade_status',flash:'xqsystem/flash_status'}};
export const SYSTEM_CONTEXT={
  otaSettings:['misystem/ota'],privacyProgram:['xqsystem/privacy'],pushSettings:['xqsystem/push_settings'],
  forceHttps:['xqsystem/get_access_force_https'],timezone:['misystem/sys_time'],deviceNotify:['misystem/devicelist'],
  reboot:[],factoryReset:[],onlineUpgrade:[],firmwareFlash:[],restoreApply:[],
};
export const RESTORE_LABELS={mi_basic_info:'Имя и пароль администратора',mi_wifi_info:'Wi-Fi',mi_network_info:'Подключение к Интернету',mi_lan_info:'Локальная сеть и DHCP',mi_arn_info:'Защита сети',mi_access_info:'Доступ к управлению'};
const fail=message=>{throw new PanelError(message);};
const fresh=value=>value&&Number.isFinite(value.at)&&value.at<=Date.now()+1000&&Date.now()-value.at<600000;
export function buildSystemPlan(action,data,context={}){
  if(!Object.hasOwn(SYSTEM_CONTEXT,action))return null;
  if(!data||typeof data!=='object'||Array.isArray(data))fail('Некорректная форма.');
  const steps=[],changes=[];let notice='',wait=0,reauth=false,message='';
  const step=(path,params={},method='POST')=>steps.push({path,params,method});
  const change=(label,value)=>changes.push({label,value:String(value)});
  if(action==='otaSettings'){
    const auto=flag(data.on),plugin=flag(data.plugins),time=integer(data.hour,0,23,'Час обновления');
    step('misystem/set_ota',{auto,plugin,time});change('Автообновление прошивки',auto==='1'?'Включить':'Выключить');change('Обновление плагинов',plugin==='1'?'Автоматически':'Вручную');change('Час обновления',time+':00');
    notice='Включение разрешает будущие автоматические обновления и перезагрузки роутера и узлов Mesh. Немедленная установка не запускается.';
  }else if(action==='privacyProgram'){
    const on=flag(data.on);step('xqsystem/set_privacy_new',{privacy:on});change('Программа улучшения Xiaomi',on==='1'?'Участвовать':'Не участвовать');notice='Меняется штатное согласие на участие в программе. Это не общий выключатель всех обращений роутера к Xiaomi.';
  }else if(action==='pushSettings'){
    const auth=flag(data.on),quiet=flag(data.quiet);step('xqsystem/push_switch',{auth,quiet});change('Уведомления безопасности',auth==='1'?'Включить':'Выключить');change('Тихие уведомления',quiet==='1'?'Включить':'Выключить');notice='Получение push зависит от привязки роутера к Xiaomi Home. Настройка не меняет проверку пароля администратора.';
  }else if(action==='deviceNotify'){
    const address=mac(data.mac),on=flag(data.on),devices=context['misystem/devicelist']?.list||[];
    if(!devices.some(d=>String(d.mac).toUpperCase()===address))fail('Устройства нет в актуальном списке.');
    step('xqsystem/dev_notify',{mac:address,notify:on});change('Уведомления об устройстве',`${address}: ${on==='1'?'включить':'выключить'}`);notice='Доставка уведомления зависит от Xiaomi Home; отправка сообщения этим действием не проверяется.';
  }else if(action==='forceHttps'){
    const on=flag(data.on);step('xqsystem/set_access_force_https',{on});change('HTTPS штатного интерфейса',on==='1'?'Перенаправлять на HTTPS':'Не принуждать к перенаправлению');notice='Веб-служба роутера перезапустится. Панель продолжит использовать HTTPS с проверкой закреплённого сертификата.';wait=10;
  }else if(action==='timezone'){
    const zone=TIMEZONES.find(z=>z.index===data.index);if(!zone)fail('Выберите часовой пояс из списка прошивки.');
    step('misystem/set_sys_time',{timezone:zone.tz,index:zone.index});change('Часовой пояс',zone.label);notice='Изменение влияет на все расписания и журналы. Роутер перезапустит службу времени и включит синхронизацию NTP.';wait=5;
  }else if(action==='reboot'){
    if(data.confirm!=='ПЕРЕЗАПУСТИТЬ')fail('Для перезапуска введите ПЕРЕЗАПУСТИТЬ.');
    step('xqsystem/reboot',{client:'web'},'GET');change('Роутер','Перезапустить сейчас');notice='Интернет, Wi-Fi и управление временно отключатся. Не выключайте питание.';wait=120;message='Команда перезапуска принята. Дождитесь запуска роутера.';
  }else if(action==='factoryReset'){
    if(data.confirm!=='СБРОСИТЬ RD08')fail('Для сброса введите СБРОСИТЬ RD08.');
    const format=flag(data.storage);step('xqsystem/reset',{format},'GET');change('Заводской сброс','Удалить настройки сети, расписания и доступ к управлению');change('Данные хранилища',format==='1'?'Отформатировать':'Не запрашивать форматирование');notice='Настройки будут потеряны; действие может распространиться на Mesh. Потребуется первоначальная настройка и повторное подключение клиентов.';wait=120;reauth=true;message='Команда сброса принята. Потребуется первоначальная настройка роутера.';
  }else if(action==='onlineUpgrade'){
    const update=context['panel/update'];
    if(data.confirm!=='ОБНОВИТЬ RD08')fail('Для обновления введите ОБНОВИТЬ RD08.');
    if(!fresh(update)||![1,true,'1'].includes(update.info?.needUpdate))fail('Сначала получите актуальные сведения об обновлении Xiaomi.');
    const info=update.info;let url;try{url=new URL(info.downloadUrl);}catch{fail('Xiaomi не вернула корректную ссылку на прошивку.');}
    if(url.protocol!=='https:'||url.port||url.username||url.password||url.search||url.hash||!/(?:^|\.)(?:mi-img\.com|miwifi\.com)$/.test(url.hostname)||!/^[A-Za-z0-9/_.%+-]+$/.test(url.pathname)||!url.pathname.endsWith('.bin'))fail('Ответ Xiaomi не содержит поддерживаемой безопасной ссылки. Скачайте официальный файл и используйте локальное обновление.');
    const size=integer(info.fileSize,1,128*1024*1024,'Размер прошивки'),hash=text(info.hash||info.fullHash,'Хэш прошивки',64);
    if(!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(hash))fail('Xiaomi не вернула корректный хэш прошивки.');
    step('xqsystem/upgrade_rom',{url:url.href,filesize:size,hash,needpermission:'1'},'GET');change('Установить обновление Xiaomi',info.version||'Версия из ответа Xiaomi');notice='Роутер скачает, проверит и установит прошивку, затем перезагрузится. Интернет и Wi-Fi отключатся. Не выключайте питание.';wait=180;message='Штатное обновление запущено. Следите за индикатором роутера; не повторяйте команду.';
  }else if(action==='firmwareFlash'){
    const stage=context['panel/systemStaged'];
    if(data.confirm!=='ПРОШИТЬ RD08')fail('Для установки введите ПРОШИТЬ RD08.');
    if(!fresh(stage)||stage.kind!=='firmware')fail('Сначала передайте и проверьте файл прошивки штатным загрузчиком.');
    if(stage.reply?.downgrade&&!['0',0,false].includes(stage.reply.downgrade))fail('Штатный загрузчик отметил понижение версии. Оно требует отдельной проверки и здесь не запускается.');
    step('xqsystem/flash_rom',{custom:'1',recovery:flag(data.reset)},'GET');change('Установить локальную прошивку',stage.inspection.version||'Версия из загруженного файла');change('Настройки',data.reset==1?'Восстановить заводские':'Сохранить, если поддерживает обновление');change('SHA-256',stage.inspection.sha256);notice='Запись прошивки и перезагрузка прервут Интернет и Wi-Fi. В образе могут присутствовать разделы загрузчика. Не выключайте питание.';wait=180;reauth=data.reset==1;message='Команда записи прошивки принята. Не выключайте питание и не повторяйте команду.';
  }else if(action==='restoreApply'){
    const stage=context['panel/systemStaged'];
    if(data.confirm!=='ВОССТАНОВИТЬ RD08')fail('Для восстановления введите ВОССТАНОВИТЬ RD08.');
    if(!fresh(stage)||stage.kind!=='restore')fail('Сначала передайте архив штатному загрузчику.');
    const offered=Object.keys(stage.reply?.des?.keys||{});
    if(!Array.isArray(data.keys)||!data.keys.length||data.keys.some(k=>!Object.hasOwn(RESTORE_LABELS,k)||!offered.includes(k)))fail('Выберите поддерживаемые разделы из описания загруженного архива.');
    const keys=[...new Set(data.keys)];step('misystem/c_restore',{keys:keys.join(',')},'GET');change('Восстановить разделы',keys.map(k=>RESTORE_LABELS[k]).join(', '));notice='Архив должен принадлежать этому устройству. Настройки Wi-Fi, LAN, WAN или доступа могут немедленно прервать соединение. Подготовленный архив одноразовый; повтор после ошибки требует новой загрузки.';wait=45;reauth=true;message='Роутер принял восстановление. Переподключитесь к сети и войдите снова.';
  }
  if(['onlineUpgrade','firmwareFlash'].includes(action))reauth=true;
  return {steps,changes,notice,wait,reauth,message};
}
