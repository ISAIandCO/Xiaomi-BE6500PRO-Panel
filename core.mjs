import { isIP } from 'node:net';

export class PanelError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
const fail = message => { throw new PanelError(message); };
export const text = (value, name, max = 128, empty = false) => {
  if (typeof value !== 'string' || (!empty && !value.trim()) || Buffer.byteLength(value) > max || /[\x00-\x1f\x7f]/.test(value)) fail(`Проверьте поле «${name}».`);
  return value;
};
export const integer = (value, min, max, name) => {
  if (!/^-?\d+$/.test(String(value)) || +value < min || +value > max) fail(`«${name}»: допустимо от ${min} до ${max}.`);
  return String(+value);
};
export const flag = value => integer(value, 0, 1, 'Переключатель');
export const choice = (value, values, name) => values.map(String).includes(String(value)) ? String(value) : fail(`Недопустимое значение «${name}».`);
const ip = (value, empty = false) => value === '' && empty ? '' : isIP(value) === 4 ? value : fail('Введите корректный IPv4-адрес.');
export const mac = value => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(value) && !(parseInt(value.slice(0,2),16)&1) && !/^00(:00){5}$/.test(value) ? value.toUpperCase() : fail('Введите индивидуальный MAC-адрес в формате AA:BB:CC:DD:EE:FF.');
const id = value => /^[\w.-]{1,80}$/.test(String(value)) ? String(value) : fail('Некорректный идентификатор записи.');
const ipv4num = value => value.split('.').reduce((a, b) => a * 256 + +b, 0);
const inSubnet = (a, b, mask) => ((ipv4num(a) & ipv4num(mask)) >>> 0) === ((ipv4num(b) & ipv4num(mask)) >>> 0);
const isMask = value => { ip(value); const n = ipv4num(value) >>> 0; const inv = (~n) >>> 0; return n !== 0 && inv !== 0 && ((inv & (inv + 1)) >>> 0) === 0; };
export function formEncode(object) {
  const params = new URLSearchParams();
  function add(key, value) {
    if (value && typeof value === 'object') Object.entries(value).forEach(([k, v]) => add(`${key}[${k}]`, v));
    else if (value !== undefined && value !== null) params.append(key, String(value));
  }
  Object.entries(object).forEach(([k, v]) => add(k, v));
  return params.toString();
}
export function publicData(value) {
  if (Array.isArray(value)) return value.map(publicData);
  if (!value || typeof value !== 'object') return value;
  const result = {};
  for (const [k, v] of Object.entries(value)) {
    if (/password|passwd|pwd|token|secret|^key$|^sn$|^session$|^(?:wps_?)?pin$|routerid|miioDid|ssecurity|authorization|cookie|credential|private.?key/i.test(k)) {
      if (/password|passwd|pwd/i.test(k)) result.hasPassword = !!v;
    } else result[k] = typeof v === 'string' ? v.replace(/;stok=[a-z0-9]+/gi,';stok=[скрыто]') : publicData(v);
  }
  return result;
}
export const GROUPS = {
  overview: { status: 'misystem/status', wan: 'xqnetwork/wan_info', wifi: 'xqnetwork/wifi_detail_all', ports: 'misystem/get_ps_map', mlo: 'xqnetwork/get_hostap_mlo', routerName: 'misystem/router_name' },
  wifi: { wifi: 'xqnetwork/wifi_detail_all', mlo: 'xqnetwork/get_hostap_mlo', twt: 'xqnetwork/get_twt', roaming: 'xqnetwork/get_aimesh_config', channels: 'xqnetwork/get_ch_adj_enable', miot: 'xqnetwork/get_miotrelay_switch', quiet: 'xqnetwork/get_wifi_silence' },
  internet: { wan: 'xqnetwork/wan_info', ipv6: 'xqnetwork/get_wan6_v2', ipv6Info: 'xqnetwork/get_wan6_info_v2', lan6: 'xqnetwork/get_lan6_v2' },
  lan: { lan: 'xqnetwork/lan_info', dhcp: 'xqnetwork/lan_dhcp', bindings: 'xqnetwork/macbind_info' },
  devices: { devices: 'misystem/devicelist', qos: 'misystem/qos_info' },
  ports: { ports: 'misystem/get_ps_map', dualwan: 'misystem/get_ps_service?service=multiwan', iptv: 'misystem/get_ps_service?service=iptv', lag: 'misystem/get_ps_service?service=lag' },
  nat: { forwarding: 'xqsystem/portforward', upnp: 'xqsystem/upnp', dmz: 'xqsystem/dmz', lan: 'xqnetwork/lan_info' },
  services: { vpn: 'xqsystem/vpn', vpnStatus: 'xqsystem/vpn_status', ddns: 'xqnetwork/ddns', qos: 'misystem/qos_info' },
  system: { routerName: 'misystem/router_name', status: 'misystem/status', led: 'misystem/led', allled: 'misystem/allled', ethled: 'misystem/ethled', nfc: 'xqnetwork/get_nfc_info', time: 'misystem/sys_time' },
  iot: { iot: 'xqnetwork/get_iotwifi_info', wifi: 'xqnetwork/wifi_detail_all' },
  guest: { wifi:'xqnetwork/wifi_diag_detail_all', qos:'misystem/qos_info' },
  security: { acl:'xqnetwork/wifi_macfilter_info', self:'xqsystem/device_mac', ipmac:'xqnetwork/ipmac_check_status', gateway:'xqnetwork/get_gw_security', webAccess:'misystem/web_access_info', ipv6Firewall:'xqnetwork/get_ipv6_firewall', wps:'xqnetwork/get_wps_info' },
  mesh: { topology:'misystem/topo_graph', children:'misystem/child_mesh_infos', backhaul:'misystem/get_mesh_bh_mode', binding:'xqnetwork/get_sta_bindinfo' },
  parental: { users:'misystem/mipctl_get_user_list', devices:'misystem/mipctl_get_device_list' },
  diagnostics: { status:'misystem/status', router:'misystem/router_info', ports:'xqnetwork/get_port_state', wan:'xqnetwork/wan_info', wanStats:'xqnetwork/wan_statistics', ipv6:'xqnetwork/get_wan6_info_v2', ipv6Lan:'xqnetwork/get_lan6_v2', wifi:'xqnetwork/wifi_diag_detail_all', features:'misystem/feature_info' },
};
Object.assign(GROUPS.devices, {self:'xqsystem/device_mac'});
Object.assign(GROUPS.ports, {links:'xqnetwork/get_port_state', wanSpeed:'xqnetwork/wan_speed', policies:'xqnetwork/get_multiwan_dev_policies'});
Object.assign(GROUPS.services, {smartvpn:'misystem/smartvpn_info'});
Object.assign(GROUPS.internet, {ipv6Switch:'xqnetwork/get_wan6_switch_v2'});
Object.assign(GROUPS.diagnostics, {weakSignal:'xqnetwork/get_wifi_weak'});
Object.assign(GROUPS.security, {center:'sec_center/overview', attacks:'anti_attack/get_status', filter:'url_fw/get_status', policies:'url_fw/show_policy', deviceProtection:'device_security/overview'});
Object.assign(GROUPS.system, {scenes:'xqsmarthome/request_smartcontroller'});
GROUPS.plugins={plugins:'xqsystem/installed_plug'};
GROUPS.schedules={scenes:'xqsmarthome/request_smartcontroller',time:'misystem/sys_time'};
// The tunnel is exposed only with this fixed read command, never a browser-supplied payload.
export const READ_PARAMS={'xqsmarthome/request_smartcontroller':{payload:JSON.stringify({command:'get_scene_setting'})}};
export const SIMPLE_ACTIONS = {
  mlo: ['xqnetwork/set_hostap_mlo', 'mlo_enable', 'MLO'], twt: ['xqnetwork/set_twt', 'on', 'TWT'],
  meshChannels: ['xqnetwork/set_ch_adj_enable', 'ch_adj_en', 'Разные каналы Mesh'], miot: ['xqnetwork/miotrelay_switch', 'on', 'Подключение MiOT'],
  quiet: ['xqnetwork/set_wifi_silence', 'on', 'Тихий режим Wi-Fi'], nfc: ['xqnetwork/set_nfc_status', 'nfc_enable', 'NFC'],
  led: ['misystem/led', 'on', 'Индикатор состояния', 'GET'], allled: ['misystem/allled', 'on', 'Все индикаторы', 'GET'],
  ethled: ['misystem/ethled', 'on', 'Индикаторы Ethernet', 'GET'], upnp: ['xqsystem/upnp_switch', 'switch', 'UPnP', 'GET'],
  qosSwitch: ['misystem/qos_switch', 'on', 'QoS', 'GET'],
  iotPriority: ['xqnetwork/set_iotwifi_highprio','high_priority_access','Приоритет IoT'],
  wifiAx: ['xqnetwork/set_wifi_ax','ax','Wi-Fi 6/7 (802.11ax)'],
  ipmac: ['xqnetwork/ipmac_check_enable','enable','Проверка IP/MAC'],
  gateway: ['xqnetwork/set_gw_security','on','Защита шлюза'],
  ipv6Firewall: ['xqnetwork/set_ipv6_firewall','mode','Межсетевой экран IPv6'],
  vpnAuto: ['xqsystem/set_vpnauto','auto','Автоподключение VPN','GET'],
  attackScan: ['anti_attack/set_scan','enable','Защита от сканирования'],
  attackDos: ['anti_attack/set_dos','enable','Защита от DoS'],
  attackRpfilter: ['anti_attack/set_rpfilter','enable','Проверка обратного маршрута'],
};
export const CONTEXT = { wifi: ['xqnetwork/wifi_detail_all'], wan: ['xqnetwork/wan_info'], dhcp: ['xqnetwork/lan_info'], lanIp: ['xqnetwork/lan_info'], bind: ['xqnetwork/lan_info'], natAdd: ['xqnetwork/lan_info'], dmz: ['xqnetwork/lan_info'], lag: ['misystem/get_ps_map', 'misystem/get_ps_service?service=lag'], iptv: ['misystem/get_ps_map'], dualwan: ['misystem/get_ps_map'], routerName: ['misystem/router_name'] };
Object.assign(CONTEXT, {
  sceneSave:['xqsmarthome/request_smartcontroller','misystem/sys_time'], sceneToggle:['xqsmarthome/request_smartcontroller'], sceneDelete:['xqsmarthome/request_smartcontroller'],
  attackScan:['anti_attack/get_status'], attackDos:['anti_attack/get_status'], attackRpfilter:['anti_attack/get_status'], contentFilter:['url_fw/get_status'],
  iot:['xqnetwork/get_iotwifi_info'], guest:['xqnetwork/wifi_diag_detail_all'], iotPriority:['xqnetwork/get_iotwifi_info'], wifiAx:['xqnetwork/wifi_detail_all'], beamforming:['xqnetwork/wifi_detail_all'],
  deviceName:['misystem/devicelist'], deviceAccess:['misystem/devicelist','xqsystem/device_mac'],
  deviceQos:['misystem/qos_info'], qosUnlimit:['misystem/qos_info'],
  acl:['xqnetwork/wifi_macfilter_info','xqsystem/device_mac'], aclEntry:['xqnetwork/wifi_macfilter_info','xqsystem/device_mac'],
  ipmac:['xqnetwork/ipmac_check_status'], gateway:['xqnetwork/get_gw_security'], ipv6Firewall:['xqnetwork/get_ipv6_firewall'],
  backhaul:['misystem/get_mesh_bh_mode'],
  webAccess:['misystem/web_access_info','xqsystem/device_mac'], webAccessEntry:['misystem/web_access_info','xqsystem/device_mac'], clock:['misystem/sys_time'],
  wanMac:['xqnetwork/wan_info'], wanSpeed:['xqnetwork/wan_speed'], natRange:['xqnetwork/lan_info','xqsystem/portforward'],
  ipv6:['xqnetwork/get_wan6_v2'], lan6:['xqnetwork/get_lan6_v2'],
  vpnEdit:['xqsystem/vpn'], vpnAuto:['xqsystem/vpn'], smartvpn:['misystem/smartvpn_info'], smartvpnMac:['misystem/smartvpn_info'], smartvpnUrl:['misystem/smartvpn_info'],
  ddnsEdit:['xqnetwork/ddns'], parentalAdd:['misystem/mipctl_get_user_list'], parentalEdit:['misystem/mipctl_get_user_list'], parentalDelete:['misystem/mipctl_get_user_list'], parentalDevices:['misystem/mipctl_get_user_list'], parentalPause:['misystem/mipctl_get_user_list'], parentalHosts:['misystem/mipctl_get_user_list'], parentalSchedule:['misystem/mipctl_get_user_list'],
});
Object.assign(CONTEXT,{
  dhcp:['xqnetwork/lan_info','xqnetwork/lan_dhcp','xqnetwork/macbind_info'],bind:['xqnetwork/lan_info','xqnetwork/macbind_info'],unbind:['xqnetwork/macbind_info'],
  natAdd:['xqnetwork/lan_info','xqsystem/portforward'],natDelete:['xqsystem/portforward'],
  vpnAdd:['xqsystem/vpn'],vpnConnect:['xqsystem/vpn','xqsystem/vpn_status'],vpnDelete:['xqsystem/vpn'],
  ddnsAdd:['xqnetwork/ddns'],ddnsDelete:['xqnetwork/ddns'],ddnsSwitch:['xqnetwork/ddns'],roaming:['xqnetwork/get_aimesh_config'],
});
for (const [action, key] of Object.entries({mlo:'mlo',twt:'twt',meshChannels:'channels',miot:'miot',quiet:'quiet',nfc:'nfc',led:'led',allled:'allled',ethled:'ethled',upnp:'upnp',qosSwitch:'qos',qosMode:'qos',bandwidth:'qos'})) {
  const route=Object.values(GROUPS).find(group=>group[key])?.[key]; if(route)CONTEXT[action]=[route];
}
export const namesafe = value => { text(value,'Название',64); if (/[`$;&|<>\\]/.test(value)) fail('Название содержит недопустимые символы.'); return value; };
const host = value => /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i.test(value) && !value.includes('..') ? value : fail('Введите имя узла или IPv4-адрес без пути и порта.');
const ip6 = (value, empty=false) => value === '' && empty ? '' : isIP(value) === 6 && !value.includes('%') ? value : fail('Введите IPv6-адрес.');
const lines = value => typeof value === 'string' && value.length <= 8192 ? [...new Set(value.split(/[\s,;]+/).filter(Boolean))] : fail('Слишком длинный список.');
export function buildPlan(action, data, context = {}) {
  text(action,'Операция',64);
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('Некорректная форма.');
  const steps = [], changes = []; let notice = ''; let wait = 0;
  const step = (path, params = {}, method = 'POST') => steps.push({ path, params: ['xqnetwork/set_all_wifi','xqnetwork/set_wifi_ax','xqnetwork/set_wifi_txbf'].includes(path)?{...params,user_confirm:'1'}:params, method });
  const change = (label, value) => changes.push({ label, value: String(value) });
  const lanInfo = context['xqnetwork/lan_info']?.info?.ipv4?.[0];
  const localIp = value => { ip(value); if (lanInfo && (!inSubnet(value, lanInfo.ip, lanInfo.mask) || value === lanInfo.ip)) fail('Нужен адрес устройства в локальной подсети, отличный от адреса роутера.'); return value; };
  const selfMac = String(context['xqsystem/device_mac']?.mac || '').toUpperCase();
  const knownDevice = value => { const address=mac(value); if(!(context['misystem/devicelist']?.list||context['misystem/qos_info']?.list||[]).some(d=>String(d.mac).toUpperCase()===address)) fail('Устройство отсутствует в актуальном списке. Обновите данные.'); return address; };
  if (Object.hasOwn(SIMPLE_ACTIONS,action)) {
    if(action==='mlo'&&+context['xqnetwork/get_hostap_mlo']?.mlo_support===0)fail('MLO не поддерживается устройством.');
    if(action==='nfc'&&+context['xqnetwork/get_nfc_info']?.nfc_support===0)fail('NFC не поддерживается устройством.');
    const [path, param, label, method] = SIMPLE_ACTIONS[action]; const on = flag(data.on);
    step(path, { [param]: on }, method); change(label, on === '1' ? 'Включить' : 'Выключить');
    if (['mlo', 'twt', 'meshChannels', 'miot', 'quiet','wifiAx'].includes(action)) { notice = 'Wi-Fi может временно переподключиться. На DFS-каналах проверка эфира CAC может занять до 10 минут. Проверьте совместимость клиентов.'; wait = 30; }
    if(action==='ipmac')notice='Проверяйте список постоянных IP перед включением: устройства с несовпадающими IP/MAC могут потерять доступ.';
    if(action==='ipv6Firewall')notice=on==='1'?'Входящие подключения IPv6 будут фильтроваться.':'Устройства с глобальными IPv6-адресами могут стать доступны из Интернета.';
  } else if (action === 'wifi') {
    const current = context['xqnetwork/wifi_detail_all'];
    if (!Array.isArray(data.radios) || data.radios.length !== current?.info?.length) fail('Состав радиомодулей изменился. Обновите страницу.');
    const params = { bsd: flag(data.bsd) }; let enabled = 0;
    current.info.forEach((old, i) => {
      const r = data.radios[i]; if (r.ifname !== old.ifname) fail('Обновите данные Wi-Fi перед сохранением.');
      const n = i + 1; const enc = choice(r.encryption, ['none', 'psk2', 'mixed-psk', 'ccmp', 'psk2+ccmp'], 'Защита');
      const channels = old.available_channels?.map(x => String(x.c)) || ['0'];
      const channel = choice(r.channel, channels, 'Канал');
      const channelBands = old.available_channels?.find(x => String(x.c) === channel)?.b;
      const bandList = [...new Set(['0', ...(channelBands || old.channelInfo?.bandList || []).map(String)])];
      const password = r.password === '' ? old.password : text(r.password, 'Пароль Wi-Fi', 63);
      if (enc !== 'none' && (!password || Buffer.byteLength(password) < 8 || Buffer.byteLength(password) > 63)) fail('Пароль Wi-Fi должен содержать от 8 до 63 байт.');
      const on = flag(r.on); enabled += +on;
      const ssid = text(r.ssid, 'Название Wi-Fi', 32);
      Object.assign(params, { [`on${n}`]: on, [`ssid${n}`]: ssid, [`encryption${n}`]: enc, [`pwd${n}`]: enc === 'none' ? '' : password,
        [`channel${n}`]: channel, [`bandwidth${n}`]: choice(r.bandwidth, bandList, 'Ширина канала'), [`hidden${n}`]: flag(r.hidden), [`txpwr${n}`]: choice(r.txpwr, ['min','mid','max'], 'Мощность') });
      change(`${i === 0 ? '2,4' : '5'} ГГц`, `${on === '1' ? ssid : 'Выключить'} · ${enc} · канал ${channel === '0' ? 'авто' : channel}`);
      if (r.password) change(`Пароль ${i + 1}`, 'Заменить (не отображается)');
    });
    if (params.bsd === '1' && data.radios.some(r => r.ssid !== data.radios[0].ssid || r.encryption !== data.radios[0].encryption)) fail('Для единой сети задайте одинаковые имена и защиту обоих диапазонов.');
    if (params.bsd === '1' && params.pwd1 !== params.pwd2) fail('Для единой сети задайте одинаковые пароли обоих диапазонов.');
    params.isDFS = (+params.channel2 >= 52 && +params.channel2 <= 64 || params.bandwidth2 === '0') && params.on2 === '1' ? '1' : '0';
    step('xqnetwork/set_all_wifi', params); change('Единая сеть', params.bsd === '1' ? 'Да' : 'Нет');
    notice = enabled ? 'Изменение Wi-Fi временно отключит беспроводные устройства. На DFS-каналах проверка эфира CAC может занять до 10 минут.' : 'Оба диапазона будут выключены. Продолжайте только при проводном подключении.'; wait = 40;
  } else if (action === 'roaming') {
    const params = { manual_roaming_setting: flag(data.on), roam_rssi_thr_2g: integer(data.rssi2, -95, -45, 'Порог 2,4 ГГц'), roam_rssi_thr_5g: integer(data.rssi5, -95, -45, 'Порог 5 ГГц') };
    step('xqnetwork/set_aimesh_config', params); change('Ручной роуминг', params.manual_roaming_setting === '1' ? `${params.roam_rssi_thr_2g} / ${params.roam_rssi_thr_5g} dBm` : 'Выключить'); notice = 'Порог определяет, когда клиенту предложат сменить точку Mesh.';
  } else if (action === 'wan') {
    const old = context['xqnetwork/wan_info']?.info?.details || {};
    const wanType = choice(data.wanType, ['dhcp','pppoe','static'], 'Тип подключения');
    const params = { wanType, autoset: flag(data.autoset), dns1: ip(data.dns1 || '', true), dns2: ip(data.dns2 || '', true) };
    if (params.autoset === '0' && !params.dns1) fail('Укажите основной DNS.');
    if (wanType === 'static') { Object.assign(params, { staticIp: ip(data.staticIp), staticMask: ip(data.staticMask), staticGateway: ip(data.staticGateway) }); if (!isMask(params.staticMask) || !inSubnet(params.staticIp, params.staticGateway, params.staticMask)) fail('Проверьте маску и шлюз статического подключения.'); }
    if (wanType === 'pppoe') {
      const password = data.pppoePwd || old.password || old.pppoePwd;
      if (!password) fail('Введите пароль PPPoE.');
      Object.assign(params, { pppoeName: text(data.pppoeName, 'Логин PPPoE'), pppoePwd: text(password, 'Пароль PPPoE'), special: flag(data.special ?? 0), mtu: integer(data.mtu || 1480, 576, 1492, 'MTU'), service: text(data.service || '', 'Сервис', 128, true) });
    }
    step('xqnetwork/set_wan', params); change('Подключение', wanType.toUpperCase()); change('DNS', params.autoset === '1' ? 'Автоматически' : [params.dns1,params.dns2].filter(Boolean).join(', ')); notice = 'Интернет временно отключится при применении параметров WAN.'; wait = 15;
  } else if (action === 'ipv6') {
    const mode = choice(data.mode, ['off','native','dhcpv6','pppoev6','static','passthrough','relay','pi_relay','6in4','6to4','6rd','464xlat'], 'Режим IPv6');
    const params={ipv6_mode:mode,automode:mode==='native'?'1':'0'};
    if(!['off','native','passthrough','relay','pi_relay'].includes(mode))Object.assign(params,{dns1:ip6(data.dns1||'',true),dns2:ip6(data.dns2||'',true),ip6prefix:ip6(data.prefix||'',mode!=='static'),ip6prefixlen:integer(data.prefixlen??64,1,64,'Префикс'),nat6_enabled:flag(data.nat6??0)});
    if(mode==='static')Object.assign(params,{ip6addr:ip6(data.ip6addr),ip6gw:ip6(data.ip6gw)});
    if(mode==='pppoev6'){params.use_pppoev4=flag(data.usePPPoEv4??1);if(params.use_pppoev4==='0')Object.assign(params,{ipv6DialAccount:text(data.username,'Логин IPv6'),ipv6DialPassword:text(data.password||context['xqnetwork/get_wan6_v2']?.wan6_cfg?.password,'Пароль IPv6')});}
    if(params.nat6_enabled==='1'&&!params.ip6prefix)fail('Для NAT6 задайте локальный префикс.');
    if(mode==='6in4'){
      Object.assign(params,{peeraddr:ip(data.peeraddr),ip6addr:ip6(data.ip6addr),ip6prefix:ip6(data.prefix)});
      if(data.tunnelid)Object.assign(params,{tunnelid:integer(data.tunnelid,1,2147483647,'ID туннеля'),ipv6DialAccount:text(data.username,'Логин туннеля'),ipv6DialPassword:text(data.password,'Пароль туннеля')});
    }
    if(mode==='6to4')params.peeraddr=ip(data.peeraddr||'192.88.99.1');
    if(mode==='6rd'){params.use_dhcp=flag(data.useDHCP??1);if(params.use_dhcp==='0')Object.assign(params,{peeraddr:ip(data.peeraddr),ip6prefix:ip6(data.prefix)});}
    if(mode==='464xlat')params.ip6prefix=ip6(data.prefix);
    step('xqnetwork/set_wan6_v2', params); change('IPv6', mode); notice = 'Изменятся IPv6-подключение и адреса клиентов.'; wait = 15;
  } else if (action === 'dhcp') {
    if (!lanInfo || !isMask(lanInfo.mask)) fail('Сначала прочитайте настройки LAN.');
    if(data.startip!==undefined){
      const startip=localIp(data.startip),endip=localIp(data.endip);const start=ipv4num(startip),end=ipv4num(endip);const network=(ipv4num(lanInfo.ip)&ipv4num(lanInfo.mask))>>>0;const broadcast=(network|~ipv4num(lanInfo.mask))>>>0;
      if(start> end||start===network||end===broadcast||end-start>=1000||(ipv4num(lanInfo.ip)>=start&&ipv4num(lanInfo.ip)<=end))fail('Диапазон должен содержать до 1000 адресов и исключать роутер, адрес сети и broadcast.');
      step('xqnetwork/set_lan_dhcp',{startip,endip,ignore:String(1-+flag(data.on)),leasetime:integer(data.minutes,2,10080,'Аренда DHCP')+'m',dns1:ip(data.dns1||'',true),dns2:ip(data.dns2||'',true),router:ip(data.router||'',true)});
      change('DHCP',data.on==1?`${startip}–${endip}`:'Выключить');notice='Прошивка перезапускает сетевые службы при изменении DHCP. Связь временно прервётся.';wait=30;
    }else{
    if (lanInfo.mask !== '255.255.255.0') fail('Для этой подсети укажите полные начальный и конечный IP.');
    const start = integer(data.start, 2, 254, 'Начало диапазона'), end = integer(data.end, 2, 254, 'Конец диапазона');
    const routerOctet = +lanInfo.ip.split('.').at(-1);
    if (+end < +start || (routerOctet >= +start && routerOctet <= +end)) fail('Диапазон DHCP некорректен или включает адрес роутера.');
    const params = { start, end, limit: String(+end - +start + 1), leasetime: integer(data.minutes, 2, 10080, 'Аренда DHCP') + 'm', ignore: String(1 - +flag(data.on)), dns1: ip(data.dns1 || '', true), dns2: ip(data.dns2 || '', true), router: ip(data.router || '', true) };
    step('xqnetwork/set_lan_dhcp', params); change('DHCP', data.on == 1 ? `${start}-${end}, ${data.minutes} мин.` : 'Выключить'); notice = 'Прошивка перезапускает сетевые службы при изменении DHCP. Связь временно прервётся.';wait=30;
    }
  } else if (action === 'lanIp') {
    const address = ip(data.ip), mask = ip(data.mask); if (!isMask(mask)) fail('Неверная маска сети.');
    step('xqnetwork/set_lan_ip', { ip: address, mask }, 'GET'); change('LAN', `${address} / ${mask}`); notice = 'Роутер может перезагрузиться. При смене адреса обновите host в router-config.json и перезапустите панель. Брони DHCP и пробросы могут потребовать настройки заново.'; wait = 60;
  } else if (action === 'bind') {
    const entry = { mac: mac(data.mac), ip: localIp(data.ip), name: text(data.name, 'Имя устройства', 64) };
    step('xqnetwork/mac_bind', { data: JSON.stringify([entry]) }); change('Постоянный IP', `${entry.name}: ${entry.ip} (${entry.mac})`);
  } else if (action === 'unbind') { step('xqnetwork/mac_unbind', { mac: mac(data.mac) }); change('Снять бронь DHCP', data.mac);
  } else if (action === 'natAdd') {
    const params = { name: text(data.name, 'Название', 64), proto: choice(data.proto, [1,2,3], 'Протокол'), sport: integer(data.sport, 1, 65535, 'Внешний порт'), dport: integer(data.dport, 1, 65535, 'Внутренний порт'), ip: localIp(data.ip) };
    step('xqsystem/add_redirect', params); step('xqsystem/redirect_apply', {}, 'GET'); change('Проброс порта', `${params.sport} → ${params.ip}:${params.dport}`); notice = 'Этот порт станет доступен со стороны WAN при наличии внешнего адреса и разрешений провайдера.';
  } else if (action === 'natDelete') {
    step('xqsystem/delete_redirect', { port: integer(data.port, 1, 65535, 'Порт'), proto: choice(data.proto, [1,2,3], 'Протокол') }); step('xqsystem/redirect_apply', {}, 'GET'); change('Удалить проброс', data.port);
  } else if (action === 'dmz') {
    const on = flag(data.on); step(on === '1' ? 'xqsystem/set_dmz' : 'xqsystem/dmz_off', on === '1' ? { ip: localIp(data.ip) } : {}, on === '1' ? 'POST' : 'GET');
    if(on === '0') step('xqsystem/dmz_reload', {}, 'GET');
    change('DMZ', on === '1' ? data.ip : 'Выключить'); notice = on === '1' ? 'Входящие соединения WAN будут направляться на выбранное устройство.' : ''; wait = 15;
  } else if (action === 'lag' || action === 'iptv') {
    const on = flag(data.on); const ports = Array.isArray(data.ports) ? data.ports.map(x => choice(x, [1,2,3,4], 'Порт')) : [];
    if (new Set(ports).size !== ports.length || (on === '1' && ports.length !== (action === 'lag' ? 2 : 1))) fail(action === 'lag' ? 'Выберите два разных LAN-порта.' : 'Выберите один порт IPTV.');
    const map = context['misystem/get_ps_map']?.ports || [];
    if (on === '1' && ports.some(p => /WAN/.test(map.find(x => String(x.port) === p)?.service || ''))) fail('Нельзя занять порт активного WAN.');
    if (on === '1' && ports.some(p => !['LAN','游戏网口','GAME',action === 'lag'?'LAG':'IPTV'].includes(map.find(x => String(x.port) === p)?.service))) fail('Выбранный порт занят другой службой.');
    const params = { service: action, enable: on, ports: on === '1' ? ports.join(' ') : '' };
    if (action === 'lag') params.mode = String(context['misystem/get_ps_service?service=lag']?.lag?.mode ?? 2);
    else Object.assign(params, { profile: choice(data.profile ?? 0, [0,1], 'Профиль IPTV'), vid: data.profile == 1 ? '0' : integer(data.vid, 1, 4094, 'VLAN ID'), priority: data.profile == 1 ? '0' : integer(data.priority ?? 0, 0, 7, 'Приоритет VLAN') });
    step('misystem/set_ps_service', params); change(action === 'lag' ? 'Агрегация LAN' : 'IPTV', on === '1' ? `Порты ${ports.join(', ')}` : 'Выключить'); notice = 'Ethernet-соединения могут временно прерваться. Для LAG настройте агрегацию на подключённом устройстве.'; wait = 30;
  } else if (action === 'dualwan') {
    const on = flag(data.on), a = choice(data.wan1, [1,2,3,4], 'WAN1'), b = choice(data.wan2, [1,2,3,4], 'WAN2'); if (on === '1' && a === b) fail('WAN1 и WAN2 должны использовать разные порты.');
    const map = context['misystem/get_ps_map']?.ports || [];
    if (on === '1' && [a,b].some(p => !['LAN','游戏网口','GAME','WAN','WAN1','WAN2'].includes(map.find(x => String(x.port) === p)?.service))) fail('Освободите выбранный порт от IPTV или агрегации LAN.');
    const band1=integer(data.band1||0,on==='1'?1:0,10000,'Скорость WAN1'),band2=integer(data.band2||0,on==='1'?1:0,10000,'Скорость WAN2');
    if(on==='1'&&Math.max(+band1,+band2)/Math.min(+band1,+band2)>100)fail('Отношение скоростей WAN должно быть не больше 100:1.');
    step('misystem/set_ps_service', { service: 'multiwan', enable: on, port_map: on === '1' ? [{name:'WAN1',port:a},{name:'WAN2',port:b}] : [{name:'WAN1',port:a},{name:'WAN2',port:'-1'}], policy: {mode: choice(data.mode, [0,1,2,3,4], 'Режим Dual WAN'), bandwidth_wan1:band1, bandwidth_wan2:band2} });
    change('Dual WAN', on === '1' ? `WAN1: порт ${a}, WAN2: порт ${b}` : 'Выключить'); notice = 'Изменятся роли Ethernet-портов. Интернет может временно отключиться.'; wait = 30;
  } else if (action === 'vpnAdd' || action === 'vpnEdit') {
    const old=action==='vpnEdit'?(context['xqsystem/vpn']?.list||[]).find(x=>String(x.id)===String(data.id)):null;
    if(action==='vpnEdit'&&!old)fail('Профиль VPN больше не существует.');
    step('xqsystem/set_vpn', { ...(old?{id:id(data.id)}:{}), oname: namesafe(data.oname), proto: choice(data.proto, ['pptp','l2tp'], 'VPN'), server: host(data.server), username: text(data.username, 'Логин'), password: text(data.password||old?.password, 'Пароль') }); change(old?'Изменить VPN':'Добавить VPN', `${data.oname} · ${data.proto.toUpperCase()}`);
  } else if (action === 'vpnConnect' || action === 'vpnDelete') {
    step(action === 'vpnDelete' ? 'xqsystem/del_vpn' : 'xqsystem/vpn_switch', { id: id(data.id), ...(action === 'vpnConnect' ? {conn:flag(data.on)} : {}) }, 'GET'); change('VPN', action === 'vpnDelete' ? 'Удалить профиль' : data.on == 1 ? 'Подключить' : 'Отключить'); notice = 'Маршруты через штатный VPN могут изменить доступ к Интернету.';
  } else if (action === 'ddnsAdd' || action === 'ddnsEdit') {
    const old=action==='ddnsEdit'?(context['xqnetwork/ddns']?.list||[]).find(x=>String(x.id)===String(data.id)):null;
    if(action==='ddnsEdit'&&!old)fail('Запись DDNS больше не существует.');
    step(action==='ddnsEdit'?'xqnetwork/ddns_edit':'xqnetwork/ddns_add', { id: choice(data.id, [1,2,3,4,5,6,7,8,9], 'Провайдер DDNS'), username: data.id == 8 ? 'Bearer' : text(data.username, 'Логин / ID / Bearer'), password: text(data.password||old?.password, 'Пароль / токен', 512), domain: host(data.domain), wanindex: choice(data.wanindex, ['WAN1','WAN2'], 'WAN'), iptype: choice(data.iptype, [0,1], 'Тип IP'), checkinterval: integer(data.checkinterval || 5, 1, 1440, 'Интервал, мин.'), forceinterval: integer(data.forceinterval || 1, 1, 720, 'Обновление, ч.'), enable: old?flag(old.enable):'1' }); change('DDNS', data.domain);
  } else if (action === 'ddnsDelete' || action === 'ddnsSwitch') {
    step(action === 'ddnsDelete' ? 'xqnetwork/ddns_del' : 'xqnetwork/ddns_switch', {id:id(data.id), ...(action === 'ddnsSwitch'?{on:flag(data.on)}:{})}, 'GET'); change('DDNS', action === 'ddnsDelete' ? 'Удалить запись' : data.on == 1 ? 'Включить' : 'Выключить');
  } else if (action === 'qosMode') { step('misystem/qos_mode', { mode: choice(data.mode, [3,4,5,6], 'Режим QoS') }, 'GET'); change('Режим QoS', ({3:'Автоматический',4:'Приоритет игр',5:'Приоритет сайтов',6:'Приоритет видео'})[data.mode]);
  } else if (action === 'bandwidth') {
    const rate = value => { if (!/^\d{1,5}(\.\d{1,2})?$/.test(String(value)) || +value < 0.01 || +value > 10000) fail('Скорость должна быть от 0,01 до 10000 Мбит/с.'); return String(value); };
    step('misystem/set_band', { upload: rate(data.upload), download: rate(data.download), manual:'1' }); change('Канал QoS', `${data.download} / ${data.upload} Мбит/с`);
  } else if (action === 'guest') {
    const old=context['xqnetwork/wifi_diag_detail_all']?.info?.find(x=>+x.iftype===3);
    if(!old)fail('Прошивка не возвращает параметры гостевой сети.');
    const encryption=choice(data.encryption,['none','psk2','mixed-psk'],'Защита гостевой сети');
    const password=data.password||old.password;const on=flag(data.on);
    if(encryption!=='none'&&(!password||Buffer.byteLength(password)<8||Buffer.byteLength(password)>63))fail('Укажите гостевой пароль из 8–63 байт.');
    // set_wifi silently ignores index 3 on this firmware; this endpoint calls XQGuestWifi.
    step('xqnetwork/set_wifi_without_restart',{wifiIndex:'3',ssid:text(data.ssid,'Гостевой SSID',31),encryption,pwd:encryption==='none'?'':password,on});
    change('Гостевая сеть',on==='1'?data.ssid:'Выключить');notice='Изменяется отдельная гостевая сеть. Гостевые клиенты переподключатся; защищённый гостевой режим отключает Xiaomi Wi-Fi Sharing.';wait=15;
  } else if (action === 'iot') {
    const old=context['xqnetwork/get_iotwifi_info'];if(old?.basicInfo?.length!==2)fail('Не удалось прочитать оба диапазона IoT.');
    const params={enable:flag(data.on),wifi5mode:flag(data.wifi5mode)};
    for(const [i,suffix] of ['2g','5g'].entries()){
      const encryption=choice(data['encryption'+suffix],['none','psk2','mixed-psk','ccmp','psk2+ccmp'],'Защита IoT');
      const password=data['password'+suffix]||old.basicInfo[i].password;
      if(encryption!=='none'&&(!password||Buffer.byteLength(password)<8||Buffer.byteLength(password)>63))fail('Укажите пароль IoT из 8–63 байт.');
      Object.assign(params,{['ssid'+suffix]:text(data['ssid'+suffix],'SSID IoT',32),['encryption'+suffix]:encryption,['password'+suffix]:encryption==='none'?'':password});
    }
    step('xqnetwork/set_iotwifi_info',params);change('Сеть IoT',params.enable==='1'?`${params.ssid2g} / ${params.ssid5g}`:'Выключить');notice='IoT Wi-Fi не обеспечивает изоляцию гостевой сети. Wi-Fi временно переподключится.';wait=30;
  } else if (action === 'deviceName') {
    const address=knownDevice(data.mac);step('xqsystem/set_device_nickname',{mac:address,name:namesafe(data.name)},'GET');change('Имя устройства',`${address}: ${data.name}`);
  } else if (action === 'deviceAccess') {
    const address=knownDevice(data.mac),on=flag(data.on);if(!selfMac)fail('Не удалось определить MAC компьютера панели.');if(on==='0'&&address===selfMac)fail('Нельзя заблокировать компьютер, на котором запущена панель.');
    step('xqsystem/set_mac_filter',{mac:address,wan:on},'GET');change('Интернет устройства',`${address}: ${on==='1'?'разрешить':'запретить'}`);
  } else if (action === 'deviceQos' || action==='qosUnlimit') {
    const address=knownDevice(data.mac);if(+context['misystem/qos_info']?.status?.on!==1)fail('Сначала включите QoS.');
    const rate=value=>{if(!/^\d{1,8}(?:\.\d{1,2})?$/.test(String(value))||+value>10240000)fail('Лимит должен быть от 0 до 10240000 КБ/с, до двух знаков после точки.');return String(value);};
    if(action==='qosUnlimit')step('misystem/qos_offlimit',{mac:address},'GET');
    else step('misystem/qos_limits',{data:JSON.stringify([{mac:address,maxup:rate(data.upload),maxdown:rate(data.download)}])});
    change('Лимиты скорости',`${address}: ${action==='qosUnlimit'?'снять':data.download+' / '+data.upload+' КБ/с (0 — без лимита)'}`);
  } else if (action === 'acl' || action==='aclEntry') {
    const acl=context['xqnetwork/wifi_macfilter_info'];const model=choice(data.model,[0,1],'Список');
    if(action==='acl'){
      const enable=flag(data.on);if(enable==='1'&&!selfMac)fail('Не удалось определить MAC компьютера панели.');
      const list=acl?.macfilter||[];const contains=list.some(x=>String(typeof x==='string'?x:x.mac).toUpperCase()===selfMac);
      if(enable==='1'&&model==='1'&&(!list.length||!contains))fail('Перед включением белого списка добавьте в него MAC компьютера панели.');
      if(enable==='1'&&model==='0'&&contains)fail('Удалите компьютер панели из чёрного списка.');
      if(String(acl?.model)!==model&&enable==='1')fail('Сначала смените режим с выключенным фильтром, затем заполните список.');
      step('xqnetwork/set_wifi_macfilter',{enable,model},'GET');change('Фильтр Wi-Fi',`${enable==='1'?'Включить':'Выключить'} · ${model==='1'?'белый':'чёрный'} список`);
    }else{
      const address=mac(data.mac),option=flag(data.on);if(String(acl?.model)!==model)fail('Выбран другой режим списка. Обновите страницу.');
      if(address===selfMac&&((model==='0'&&option==='1')||(model==='1'&&option==='0'))&&+acl?.enable===1)fail('Операция отключит компьютер панели.');
      step('xqnetwork/edit_device',{mac:address,model,option},'GET');change('Список Wi-Fi',`${option==='1'?'Добавить':'Удалить'} ${address}`);
    }
    notice='Фильтрация MAC не заменяет шифрование Wi-Fi. Клиенты могут потерять доступ.';
  } else if (action === 'beamforming') {
    const on=flag(data.on);step('xqnetwork/set_wifi_txbf',{txbf:on==='1'?'3':'0'});change('MU-MIMO / Beamforming',on==='1'?'Включить':'Выключить');notice='Wi-Fi временно переподключится. На DFS-каналах проверка эфира CAC может занять до 10 минут.';wait=30;
  } else if(action==='webAccess'||action==='webAccessEntry'){
    if(!selfMac)fail('Не удалось определить MAC компьютера панели.');
    if(action==='webAccess'){
      const open=flag(data.on);step('misystem/web_access_opt',{open,mac:selfMac,opt:'0'});change('Доступ к управлению',open==='1'?'Ограничить списком MAC; добавить компьютер панели':'Все устройства LAN');
    }else{
      if(!context['misystem/web_access_info']?.open)fail('Сначала включите список доступа к управлению.');
      const address=mac(data.mac),on=flag(data.on);if(address===selfMac&&on==='0')fail('Нельзя удалить компьютер панели из списка управления.');
      step('misystem/web_access_opt',{open:'1',mac:address,opt:on==='1'?'0':'1'});change('Доступ к управлению',`${on==='1'?'Добавить':'Удалить'} ${address}`);
    }
    notice='Меняется список устройств, которым разрешено открывать интерфейс роутера.';
  } else if(action==='sceneSave'||action==='sceneToggle'||action==='sceneDelete'){
    const scenes=context['xqsmarthome/request_smartcontroller']?.scene_list;
    if(!Array.isArray(scenes))fail('Не удалось прочитать список таймеров.');
    const sceneId=data.id===''||data.id===undefined?null:+integer(data.id,1,2147483647,'Таймер');
    const old=scenes.find(s=>+s.id===sceneId),types=['normal_reboot','normal_wifi_down','guest_wifi_down'];
    if(sceneId!==null&&!old)fail('Таймер больше не существует.');
    if(old&&(!old.launch?.timer||old.action_list?.length!==1||!types.includes(old.action_list[0].type)))fail('Это составная или неподдерживаемая сцена.');
    let command;
    if(action==='sceneDelete'){
      if(!old)fail('Выберите существующий таймер.');command={command:'scene_delete',id:sceneId};change('Удалить таймер',old.name);
    }else if(action==='sceneToggle'){
      if(!old)fail('Выберите существующий таймер.');
      const enabled=flag(data.on)==='1';command={command:'scene_update',id:sceneId,name:old.name,action_list:old.action_list,launch:{...old.launch,timer:{...old.launch.timer,enabled}}};
      change('Таймер '+old.name,enabled?'Включить':'Выключить');
    }else{
      const kind=choice(data.kind,types,'Действие таймера'),name=namesafe(data.name);
      if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(data.time||''))fail('Время задаётся в формате ЧЧ:ММ.');
      if(!Array.isArray(data.days)||data.days.length>7)fail('Выберите дни недели.');
      const days=[...new Set(data.days.map(d=>+integer(d,0,6,'День недели')))].sort();let utc_time=0;
      if(!days.length){
        const zone=context['misystem/sys_time']?.time?.timezone?.match(/^(?:<[^>]+>|[A-Za-z]+)([+-]?\d{1,2})(?::(\d{2}))?$/);
        if(!zone)fail('Для однократного задания нужен распознанный часовой пояс роутера.');
        const date=text(data.date,'Дата',10);if(!/^\d{4}-\d{2}-\d{2}$/.test(date))fail('Введите дату однократного задания.');
        const local=Date.parse(date+'T'+data.time+':00Z');
        if(!Number.isFinite(local)||new Date(local).toISOString().slice(0,10)!==date)fail('Некорректная дата.');
        const hours=+zone[1],minutes=+(zone[2]||0);if(Math.abs(hours)>14||minutes>59)fail('Неизвестный часовой пояс.');
        utc_time=local+(hours*60+(zone[1].startsWith('-')?-minutes:minutes))*60000;
        if(utc_time<Date.now()+60000)fail('Однократный таймер должен запускаться позже чем через минуту.');
      }
      let targetId=sceneId;
      if(targetId===null){
        const first=kind==='normal_reboot'?30010:40000,last=kind==='normal_reboot'?30019:40999;
        for(let n=first;n<=last;n++)if(!scenes.some(s=>+s.id===n)){targetId=n;break;}
        if(targetId===null)fail('Нет свободного номера таймера в выбранном диапазоне.');
      }
      const duration=kind==='normal_reboot'?0:+integer(data.minutes,1,1439,'Продолжительность отключения, минут')*60000;
      const actionItem={...(old?.action_list[0]||{}),thirdParty:'xmrouter',type:kind,keyName:name,name:'Mi Router',delay:0,payload:{},extra:{duration}};
      command={command:old?'scene_update':'scene_setting',id:targetId,name,action_list:[actionItem],launch:{timer:{enabled:flag(data.on)==='1',time:data.time+':00',repeat:days.join(','),utc_time}}};
      change(old?'Изменить таймер':'Создать таймер',name);change('Действие',({normal_reboot:'Перезагрузка',normal_wifi_down:'Отключить основные Wi-Fi',guest_wifi_down:'Отключить гостевой Wi-Fi'})[kind]);
      change('Начало',`${data.date&&!days.length?data.date+' ':''}${data.time} · ${days.length?days.map(i=>['Вс','Пн','Вт','Ср','Чт','Пт','Сб'][i]).join(', '):'однократно'}`);
      if(duration)change('Отключение Wi-Fi',data.minutes+' мин.');
    }
    step('xqsmarthome/request_smartcontroller',{payload:JSON.stringify(command)});
    notice='Сохраняется задание на роутере. Перезагрузка или отключение Wi-Fi произойдут по его часам и могут прервать управление. Немедленный запуск сцены не выполняется.';
  } else if(action==='contentFilter'){
    step('url_fw/update_status',{enable:flag(data.on),auto_update:flag(data.autoUpdate)});
    change('Фильтр опасных сайтов',data.on==1?'Включить':'Выключить');change('Обновление базы',data.autoUpdate==1?'Автоматически':'Вручную');
    notice='Фильтр применяется ко всей сети. Его категории и исключения сохраняются.';
  } else if(action==='clock'){
    const value=text(data.time,'Время',19).replace('T',' ');
    if(!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)||!Number.isFinite(Date.parse(value.replace(' ','T')+'Z'))||new Date(value.replace(' ','T')+'Z').toISOString().slice(0,19)!==value.replace(' ','T'))fail('Введите корректные дату и время.');
    step('misystem/set_sys_time',{time:value});change('Время роутера',value);notice='Время используется расписаниями и журналами роутера. Часовой пояс сохраняется.';
  } else if (action === 'backhaul') {
    step('misystem/set_mesh_bh_mode',{bhmode:choice(data.mode,['auto','wired'],'Backhaul')});change('Связь Mesh',data.mode==='wired'?'Только Ethernet':'Автоматически');notice='Узлы Mesh могут временно потерять связь.';wait=30;
  } else if (action === 'wanMac') {
    step('xqnetwork/mac_clone',{mac:mac(data.mac),wan_name:'WAN1'});change('MAC WAN1',data.mac);notice='Переподключение WAN может потребовать регистрации MAC у провайдера.';wait=30;
  } else if (action === 'wanSpeed') {
    step('xqnetwork/set_wan_speed',{speed:choice(data.speed,[0,100,1000,2500],'Скорость WAN'),wan_name:'WAN1'});change('Скорость WAN1',data.speed==0?'Автосогласование':data.speed+' Мбит/с');notice='Ethernet WAN временно переподключится.';wait=15;
  } else if (action === 'natRange') {
    const fport=integer(data.fport,1,65535,'Первый порт'),tport=integer(data.tport,1,65535,'Последний порт');if(+fport>+tport)fail('Первый порт больше последнего.');
    step('xqsystem/add_range_redirect',{name:namesafe(data.name),proto:choice(data.proto,[1,2,3],'Протокол'),ip:localIp(data.ip),fport,tport});step('xqsystem/redirect_apply',{},'GET');change('Диапазон портов',`${fport}–${tport} → ${data.ip}`);notice='Диапазон станет доступен со стороны WAN.';
  } else if (action === 'lan6') {
    step('xqnetwork/set_lan6_v2',{mode:choice(data.mode,[0,1,2,3],'Объявления IPv6'),ip6assign:integer(data.prefixlen,1,64,'Префикс LAN')});change('IPv6 LAN',`${data.mode}, /${data.prefixlen}`);notice='Изменятся IPv6-адреса клиентов.';wait=15;
  } else if (action === 'smartvpn') {
    step('misystem/smartvpn_switch',{enable:flag(data.on),mode:choice(data.mode,[1,2],'Режим VPN')});change('Выборочный VPN',data.on==1?(data.mode==1?'По доменам':'По устройствам'):'Выключить');notice='Применяется к настроенному штатному VPN, изменяет маршруты.';
  } else if (action === 'smartvpnMac' || action==='smartvpnUrl') {
    const opt=flag(data.on);if(action==='smartvpnMac')step('misystem/smartvpn_mac',{opt,macs:mac(data.mac)});else step('misystem/smartvpn_url',{opt,url:host(data.domain)});
    change('Список VPN',`${opt==='1'?'Добавить':'Удалить'} ${data.mac||data.domain}`);
  } else if (action.startsWith('parental')) {
    const users=context['misystem/mipctl_get_user_list']?.user_list||[];let op;
    const user_id=action==='parentalAdd'?null:+integer(data.user_id,1,2147483647,'Профиль');
    if(user_id!==null&&!users.some(u=>+u.user_id===user_id))fail('Профиль больше не существует.');
    if(action==='parentalAdd'&&users.length>=8)fail('Прошивка допускает до восьми профилей.');
    if(action==='parentalAdd'||action==='parentalEdit')op={opt:action==='parentalAdd'?'mipctl_add_user':'mipctl_edit_user',user_name:namesafe(data.name),icon:users.find(u=>+u.user_id===user_id)?.icon||'',...(user_id===null?{}:{user_id})};
    else if(action==='parentalDelete')op={opt:'mipctl_del_user',user_id};
    else if(action==='parentalPause')op={opt:'mipctl_set_temp_deny',user_id,deny:flag(data.on)==='1'};
    else if(action==='parentalDevices')op={opt:'mipctl_set_device',user_id,devices:lines(data.macs).map(mac)};
    else if(action==='parentalHosts')op={opt:'mipctl_set_filting_net',user_id,list:lines(data.domains).map(host)};
    else if(action==='parentalSchedule'){
      const current=context['misystem/mipctl_get_deny_time']?.time_list;if(!Array.isArray(current))fail('Не удалось прочитать расписание.');
      let time_list;
      if(data.remove){if(!current.some(x=>x.id===data.remove))fail('Правило расписания больше не существует.');time_list=[{id:text(data.remove,'Правило',100)}];}
      else{
        if(current.length>=4)fail('Прошивка допускает до четырёх интервалов на профиль.');
        const minutes=value=>{if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(value||''))fail('Время задаётся в формате ЧЧ:ММ.');const [h,m]=value.split(':').map(Number);return h*60+m;};
        const start=minutes(data.start),end=minutes(data.end);if(start>=end)fail('Начало должно быть раньше конца в пределах суток.');
        if(!Array.isArray(data.days)||!data.days.length)fail('Выберите дни недели.');const days=data.days.map(x=>+integer(x,0,6,'День недели'));
        const enable=Array.from({length:7},(_,i)=>days.includes(i)?1:0);if(current.some(x=>+x.start===start&&+x.end===end&&JSON.stringify(x.enable)===JSON.stringify(enable)))fail('Такой интервал уже существует.');
        time_list=[{start,end,enable}];
      }
      op={opt:'mipctl_set_deny_time',user_id,time_list};
    }
    else fail('Эта настройка родительского контроля пока недоступна.');
    if(op.devices?.length>10)fail('В профиле допускается до 10 устройств.');if(op.list?.length>20)fail('В профиле допускается до 20 доменов.');
    const assigned=context['misystem/mipctl_get_device_list']?.list?.find(x=>+x.user_id===user_id)?.devices||[];
    if((action==='parentalPause'&&op.deny||action==='parentalSchedule'&&!data.remove)&&assigned.some(x=>String(x).toUpperCase()===selfMac))fail('Профиль включает компьютер панели; запрет может прервать управление. Сначала отвяжите этот компьютер.');
    const label={parentalAdd:'Создать профиль',parentalEdit:'Изменить профиль',parentalDelete:'Удалить профиль',parentalDevices:'Устройства профиля',parentalPause:'Приостановка доступа',parentalHosts:'Домены профиля',parentalSchedule:'Расписание доступа'}[action];
    step('misystem/mipctl_set',{opt_list:JSON.stringify([op])});change(label,data.name||users.find(u=>+u.user_id===user_id)?.user_name||user_id);
    if(op.devices)change('Полный список MAC',op.devices.join(', ')||'Очистить');if(op.list)change('Полный список доменов',op.list.join(', ')||'Очистить');
    if(action==='parentalPause')change('Интернет',op.deny?'Приостановить':'Снять ручной запрет');
    if(action==='parentalSchedule')change('Интервал',data.remove?'Удалить выбранное правило':`${data.start}–${data.end} · ${data.days.map(i=>['Пн','Вт','Ср','Чт','Пт','Сб','Вс'][+i]).join(', ')}`);
    notice='Новые ограничения могут отключить Интернет устройств профиля. Список устройств или доменов заменяется целиком.';
  } else if (action === 'routerName') {
    step('misystem/set_router_name', { name: text(data.name, 'Имя роутера', 64), locale: context['misystem/router_name']?.locale || '' }, 'GET'); change('Имя роутера', data.name);
  } else fail('Эта операция не поддерживается панелью.');
  return { steps, changes, notice, wait };
}
