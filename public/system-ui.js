export function renderSystemExtras(d,timezones,h) {
  const {el,grid,note,card,fields,formCard,details}=h;
  const ota=d.ota||{},push=d.push||{},time=d.time?.time||{};
  const currentIndex=time.index??d.time?.index??'';
  const zones=timezones.map(zone=>[zone.index,zone.label]);
  if(!zones.some(([index])=>index===currentIndex))zones.unshift(['','Выберите часовой пояс']);
  const otaCard=formCard('Автоматические обновления','Разрешает будущие обновления и перезапуски роутера и узлов Mesh.',[
    fields('on','Автоматически обновлять прошивку',ota.auto,'checkbox'),
    fields('plugins','Автоматически обновлять плагины',ota.plugin,'checkbox'),
    fields('hour','Час обновления по времени роутера',ota.time??'','number',[],{min:0,max:23,step:1,required:true}),
  ],'otaSettings');
  const timezone=formCard('Часовой пояс','Влияет на все расписания и журналы. После сохранения включается синхронизация NTP.',[
    fields('index','Часовой пояс',currentIndex,'select',zones,{full:true,required:true}),
  ],'timezone');
  const privacy=formCard('Программа улучшения Xiaomi','Штатное согласие на участие в программе улучшения пользовательского опыта. Этот флаг не управляет всеми обращениями к Xiaomi.',[
    fields('on','Участвовать в программе',d.privacy?.privacy,'checkbox',[],{full:true}),
  ],'privacyProgram');
  const notifications=formCard('Уведомления безопасности','Новые устройства и неудачные попытки входа. Получение push зависит от привязки роутера к Xiaomi Home.',[
    fields('on','Уведомления безопасности',push.auth,'checkbox'),
    fields('quiet','Тихие уведомления',push.quiet,'checkbox',[],{hint:'Штатный флаг; часы тихого режима API не сообщает.'}),
  ],'pushSettings');
  const https=formCard('HTTPS штатного интерфейса','Веб-служба роутера перезапустится. Эта панель продолжит проверять закреплённый сертификат.',[
    fields('on','Перенаправлять штатный интерфейс на HTTPS',d.https?.on,'checkbox',[],{full:true}),
  ],'forceHttps');
  const password=formCard('Пароль администратора','После изменения потребуется новый вход. Сеансы вне этой панели штатный API может сохранить.',[
    fields('oldPassword','Текущий пароль','','password',[],{required:true,maxLength:256,full:true}),
    fields('newPassword','Новый пароль','','password',[],{required:true,maxLength:63,hint:'От 8 до 63 байт; для кириллицы один символ занимает несколько байт.'}),
    fields('repeatPassword','Повтор нового пароля','','password',[],{required:true,maxLength:63}),
  ],'adminPassword');
  const updates=card('Обновление прошивки Xiaomi',el('div',{},
    note('Проверка обращается к Xiaomi и передаёт сведения о роутере. Установка запускается отдельным подтверждением.'),
    el('button',{id:'update-check',class:'secondary',type:'button',disabled:!h.info.writeSupported||!h.checkUpdate,...(h.checkUpdate?{onClick:h.checkUpdate}:{})},'Проверить наличие обновления'),
    el('div',{id:'update-result','aria-live':'polite'},note('Проверка ещё не выполнялась.'))));
  const files=card('Локальная прошивка и восстановление',el('div',{},
    note('Сначала файл проверяется на компьютере. Затем его можно передать штатному загрузчику и отдельно подтвердить установку или восстановление.'),
    note('Передача прошивки штатному загрузчику останавливает плагины ещё до проверки образа. Интернет и Wi-Fi прервутся при записи прошивки и перезапуске. Не выключайте питание.',true),
    el('div',{class:'form-grid'},
      el('div',{class:'field'},el('label',{htmlFor:'system-file-kind'},'Тип файла'),el('select',{id:'system-file-kind',name:'system-file-kind'},
        el('option',{value:'firmware'},'Официальная прошивка RD08 (.bin)'),el('option',{value:'restore'},'Штатный архив конфигурации (.tar.gz)'))),
      el('div',{class:'field'},el('label',{htmlFor:'system-file'},'Файл на компьютере'),el('input',{id:'system-file',name:'system-file',type:'file',accept:'.bin,.tar.gz,.gz','aria-describedby':'system-file-hint'}))),
    el('p',{id:'system-file-hint',class:'field-hint'},'Прошивка — только для RD08. Архив конфигурации должен принадлежать этому роутеру.'),
    el('div',{class:'form-footer'},el('button',{id:'system-file-check',class:'secondary',type:'button',disabled:!h.info.writeSupported||!h.inspectSystemFile,...(h.inspectSystemFile?{onClick:h.inspectSystemFile}:{})},'Проверить файл на компьютере')),
    el('div',{id:'system-stage','aria-live':'polite'},note('Файл ещё не выбран и не передан роутеру.'))));
  const reboot=formCard('Перезапустить роутер','Интернет, Wi-Fi и управление временно отключатся. Не выключайте питание.',[
    fields('confirm','Введите ПЕРЕЗАПУСТИТЬ','','text',[],{required:true,full:true}),
  ],'reboot');
  const reset=formCard('Заводской сброс','Настройки сети, расписания и пароль управления будут удалены. Сброс может распространиться на Mesh. Потребуется первоначальная настройка.',[
    fields('storage','Также запросить форматирование хранилища','0','checkbox',[],{full:true}),
    fields('confirm','Введите СБРОСИТЬ RD08','','text',[],{required:true,full:true}),
  ],'factoryReset');
  return el('div',{},el('h2',{class:'section-title'},'Обновления и системные настройки'),
    grid(2,otaCard,timezone),el('div',{class:'section-gap'},grid(2,privacy,notifications)),
    details('Доступ к управлению',grid(2,https,password)),
    el('div',{class:'section-gap'},updates),el('div',{class:'section-gap'},files),
    details('Перезапуск и заводской сброс',grid(2,reboot,reset)));
}

export function renderUpdate(info,h) {
  const {el,note,facts,fact,fields,formCard,raw}=h;
  if(!info)return note('Проверка ещё не выполнялась.');
  const known=[0,1,'0','1',false,true].includes(info.needUpdate),needed=[1,'1',true].includes(info.needUpdate);
  return el('div',{},note(known?(needed?'Xiaomi сообщает о доступном обновлении.':'Xiaomi не сообщает о доступном обновлении.'):'Ответ Xiaomi не содержит признака доступности обновления.',!known),
    facts(fact('Версия из ответа Xiaomi',info.version),fact('Размер файла, байт',info.fileSize)),
    needed?formCard('Установить обновление Xiaomi','Роутер скачает, проверит и установит прошивку, затем перезапустится. Интернет и Wi-Fi отключатся. Не выключайте питание.',[
      fields('confirm','Введите ОБНОВИТЬ RD08','','text',[],{required:true,full:true}),
    ],'onlineUpgrade'):null,raw('Ответ службы обновления',info));
}

export function renderSystemStage(stage,h) {
  const {el,note,card,facts,fact,fields,formCard,raw}=h;
  if(!stage)return note('Подготовленного файла нет. Проверьте файл на компьютере.');
  const inspection=stage.inspection||{},firmware=stage.kind==='firmware';
  const summary=facts(fact('Тип',firmware?'Прошивка RD08':'Архив конфигурации'),fact('Версия',inspection.version),fact('SHA-256',inspection.sha256));
  if(!stage.reply)return card('Результат локальной проверки',el('div',{},summary,
    note(inspection.valid?'Локальная проверка пройдена. Подлинность и совместимость ещё должен подтвердить штатный загрузчик.':'Локальная проверка не пройдена. Файл не будет передан роутеру.',!inspection.valid),
    raw('Результат проверки файла',inspection),
    inspection.valid?el('div',{},note(firmware?'Передача остановит плагины до проверки образа. Запись прошивки потребует следующего отдельного подтверждения.':'Передача архива не применяет настройки. Разделы для восстановления выбираются следующим шагом.',firmware),
      el('button',{class:'primary',type:'button',disabled:!h.info.writeSupported||!h.stageFile,...(h.stageFile?{onClick:event=>h.stageFile({...inspection,kind:stage.kind},event)}:{})},'Передать штатному загрузчику')):null));
  const result=el('div',{},summary,note('Файл принят штатным загрузчиком. Подготовка действует 10 минут; применение требует отдельного подтверждения.'),raw('Ответ штатного загрузчика',stage.reply));
  if(firmware){
    if(stage.reply.downgrade&&!['0',0,false].includes(stage.reply.downgrade))result.append(note('Загрузчик отметил понижение версии. Установка здесь заблокирована; нужна отдельная проверка совместимости.',true));
    else result.append(formCard('Установить загруженную прошивку','Прошивка может содержать разделы загрузчика. Запись и перезапуск прервут Интернет и Wi-Fi. Не выключайте питание.',[
      fields('reset','Восстановить заводские настройки после установки','0','checkbox',[],{full:true}),
      fields('confirm','Введите ПРОШИТЬ RD08','','text',[],{required:true,full:true}),
    ],'firmwareFlash'));
  }else{
    const labels=h.RESTORE_LABELS||{},keys=Object.keys(stage.reply.des?.keys||{}).filter(key=>Object.hasOwn(labels,key));
    if(!keys.length)result.append(note('Загрузчик не сообщил поддерживаемых разделов для восстановления.',true));
    else result.append(formCard('Восстановить выбранные настройки','Связь может прерваться сразу после применения. Архив одноразовый, в том числе после ошибки. После восстановления потребуется новый вход.',[
      fields('keys','Разделы для восстановления',[],'ports',keys.map(key=>[key,labels[key]]),{required:true,full:true,hint:'Выберите нужные разделы. В Windows удерживайте Ctrl для выбора нескольких.'}),
      fields('confirm','Введите ВОССТАНОВИТЬ RD08','','text',[],{required:true,full:true}),
    ],'restoreApply'));
  }
  return card('Файл подготовлен на роутере',result);
}
