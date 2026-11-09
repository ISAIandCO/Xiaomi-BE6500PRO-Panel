const binary=value=>['0','1'].includes(String(value));
const epoch=value=>/^\d{1,11}$/.test(String(value))&&Number.isSafeInteger(Number(value))?Number(value):null;
const decimal=value=>['number','string'].includes(typeof value)&&/^\d+(?:\.\d+)?$/.test(String(value))&&Number.isFinite(Number(value))?Number(value):null;

export function renderWps(d,h){
  const {el,card,note,facts,fact,fields,formCard,details,raw}=h;
  const state=d.wps||{},status=d.wpsStatus||{},supported=!state.error&&+state.code===0&&binary(state.wps_enable)&&binary(state.wpa3_only);
  const readable=!status.error&&+status.code===0;
  const labels={0:'Закрыт',1:'Ожидание устройства',2:'Устройство подключено',3:'Ошибка или истекло время ожидания',9:'Подключение не подтверждено'};
  const start=epoch(status.startTime),current=epoch(status.currentTime),elapsed=start!==null&&current!==null&&start>0&&current>=start?current-start:null;
  const info=card('Состояние WPS',el('div',{},facts(
    fact('Разрешение WPS',supported?(String(state.wps_enable)==='1'?'Включено':'Выключено'):'Не прочитано'),
    fact('Только WPA3',supported?(String(state.wpa3_only)==='1'?'Да':'Нет'):'Не прочитано'),
    fact('Текущее подключение',readable?(labels[status.status]||'Неизвестный статус'):'Не прочитано'),
    ...(readable&&/^(?:[\da-f]{2}:){5}[\da-f]{2}$/i.test(status.device?.mac||'')?[fact('Подключённое устройство',status.device.mac)]:[]),
    ...(readable&&elapsed!==null&&String(status.status)==='1'?[fact('С запуска, с',elapsed)]:[])),
    note('WPS PBC временно разрешает подключение совместимого устройства без ввода пароля сети. Запускайте его, когда ваше устройство готово к подключению.'),
    raw('Штатные параметры WPS',{settings:state,status})));
  return details('Подключение по WPS',info,
    formCard('Разрешение WPS','Разрешение и активное ожидание подключения регулируются отдельно.',[
      fields('on','Разрешить WPS',supported?state.wps_enable:'','checkbox',[],{full:true}),
    ],'wpsEnable'),
    supported&&String(state.wps_enable)==='1'&&String(state.wpa3_only)==='0'?formCard('Открыть окно WPS','Ближайшие совместимые устройства смогут подключаться без ввода пароля. Для отмены используйте отдельную кнопку ниже.',[
      fields('confirm','Введите ОТКРЫТЬ WPS','','text',[],{required:true,full:true}),
    ],'wpsStart'):note('Для запуска требуется включённый WPS и совместимая основная сеть с WPA2.'),
    formCard('Остановить ожидание WPS','Закрывает окно новых подключений. Уже подключённые устройства не удаляются.',[],'wpsCancel'));
}

export function renderSpeedtest(d,h){
  const {el,card,note,facts,fact,formCard,raw}=h,result=d.speedtest||{};
  const readable=!result.error&&+result.code===0;
  const up=decimal(result.up),down=decimal(result.down),complete=readable&&String(result.status)==='2'&&up!==null&&down!==null;
  const speed=value=>(value*8192/1e6).toLocaleString('ru-RU',{maximumFractionDigits:2})+' Мбит/с';
  let status='Результат не прочитан или измерение завершилось ошибкой';
  if(complete)status='Сохранённый результат роутера';
  else if(readable&&String(result.status)==='1')status='Измерение идёт или сохранённый результат ещё отсутствует';
  return card('Штатный тест скорости WAN',el('div',{},note(status),
    complete?facts(fact('Загрузка',speed(down)),fact('Отправка',speed(up))):null,
    note('Результат общий для роутера и может относиться к предыдущему запуску: API не сообщает время измерения. Для обновления используйте кнопку «Обновить» страницы.'),
    formCard('Запустить тест скорости','Тест нагружает WAN внешней отправкой и загрузкой и может замедлить Интернет у всех клиентов. Штатные серверы измерения могут быть недоступны.',[],'speedtestStart'),
    raw('Штатный результат измерения',result)));
}
