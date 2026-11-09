import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createHash, createCipheriv, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PanelError, GROUPS, READ_PARAMS, CONTEXT, buildPlan, formEncode, publicData, text, mac } from './core.mjs';
import {SECURITY_GROUPS,SECURITY_CONTEXT,buildSecurityPlan,securityDomain,logQuery} from './security-plans.mjs';
import {NETWORK_GROUPS,NETWORK_CONTEXT,buildNetworkPlan} from './network-plans.mjs';
import {inspectPluginPackage,MAX_PLUGIN_BYTES} from './plugin-package.mjs';
import {SYSTEM_GROUPS,SYSTEM_CONTEXT,TIMEZONES,buildSystemPlan} from './system-plans.mjs';
import {inspectSystemFile,MAX_FIRMWARE_BYTES,MAX_BACKUP_BYTES} from './system-file.mjs';
import {MiioLocal} from './miio-local.mjs';
import {UTILITY_GROUPS,UTILITY_CONTEXT,buildUtilityPlan} from './utility-plans.mjs';

for(const[group,routes]of Object.entries(SECURITY_GROUPS))Object.assign(GROUPS[group]??={},routes);
Object.assign(CONTEXT,SECURITY_CONTEXT);
for(const[group,routes]of Object.entries(NETWORK_GROUPS))Object.assign(GROUPS[group]??={},routes);
Object.assign(CONTEXT,NETWORK_CONTEXT);
for(const[group,routes]of Object.entries(SYSTEM_GROUPS))Object.assign(GROUPS[group]??={},routes);
Object.assign(CONTEXT,SYSTEM_CONTEXT);
for(const[group,routes]of Object.entries(UTILITY_GROUPS))Object.assign(GROUPS[group]??={},routes);
Object.assign(CONTEXT,UTILITY_CONTEXT);

const DIR = dirname(fileURLToPath(import.meta.url));
const PANEL_VERSION=JSON.parse(await readFile(join(DIR,'package.json'),'utf8')).version;
const digest = (value, mode) => createHash(mode).update(value).digest('hex');
const SERVICE_ROUTES=new Set(['service/internal/custom_host_get','service/internal/custom_host_set']);
export class Router {
  constructor(config) {
    this.config = config;
    if (!/^(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/.test(config.host)) throw new Error('host должен быть локальным IPv4-адресом.');
    this.agent = new https.Agent({ keepAlive: false, maxCachedSessions: 0, rejectUnauthorized: false });
  }
  async request(path, method = 'GET', params, binary = false, options={}) {
    if (!path.startsWith('/cgi-bin/luci/')&&!/^\/uploadfile\/cgi-bin\/luci\/;stok=[a-f0-9]+\/api\/xqsystem\/upload_(?:rom|plug)$/.test(path)) throw new PanelError('Неверный путь.', 400);
    if(options.port!==undefined&&(options.port!==8900||path!=='/cgi-bin/luci/url_fw'||method!=='GET'||params!==undefined||!options.host))throw new PanelError('Неверный порт.',400);
    const payload = Buffer.isBuffer(params)?params:params ? formEncode(params) : undefined;
    return new Promise((resolve, reject) => {
      const req = https.request({ hostname: this.config.host, port: options.port||443, path, method, agent: this.agent, rejectUnauthorized: false,
        headers: {...(payload ? { 'Content-Type':options.contentType||'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(payload) } : {}),...(options.host?{Host:securityDomain(options.host)}:{})} }, res => {
        let size = 0; const chunks = [];
        res.on('data', chunk => { size += chunk.length; if (size > (binary ? 8 : 3) * 1024 * 1024) { res.destroy(); reject(new PanelError('Слишком большой ответ роутера.', 502)); } else chunks.push(chunk); });
        res.on('error', () => reject(new PanelError('Соединение с роутером прервано.', 502)));
        res.on('end', () => { if (res.statusCode >= 300) reject(new PanelError(`API роутера недоступен (HTTP ${res.statusCode}).`, 502)); else resolve(binary ? Buffer.concat(chunks) : Buffer.concat(chunks).toString('utf8')); });
      });
      req.setTimeout(options.timeoutMs||45000, () => req.destroy(new Error('timeout')));
      req.on('error', () => reject(new PanelError('Нет ответа от роутера. Проверьте подключение и обновите данные; отправленную настройку не повторяйте автоматически.', 502)));
      // The certificate is self-signed; compare the observed router certificate before sending credentials.
      req.on('socket', socket => socket.once('secureConnect', () => {
        const actual = socket.getPeerCertificate().fingerprint256;
        if (!actual || actual !== this.config.httpsFingerprint256) {
          reject(new PanelError('Сертификат роутера изменился. Проверьте устройство и обновите отпечаток в router-config.json.', 502));
          req.destroy(); return;
        }
        req.end(payload);
      }));
    });
  }
  async api(stok, route, method = 'GET', params) {
    const service=SERVICE_ROUTES.has(route);
    if (!service&&!/^[a-z][a-z0-9_]*\/[a-z][a-z0-9_]*(?:\?service=[a-z]+)?$/.test(route)) throw new PanelError('Неверный маршрут.');
    const prefix = (stok ? `/cgi-bin/luci/;stok=${stok}/` : '/cgi-bin/luci/')+(service?'':'api/');
    let path = prefix + route;
    if (method === 'GET' && params && Object.keys(params).length) path += (path.includes('?') ? '&' : '?') + formEncode(params);
    const result = await this.request(path, method, method === 'GET' ? undefined : params);
    let body; try { body = JSON.parse(result); } catch { throw new PanelError('Роутер вернул неожиданный ответ.', 502); }
    if (+body.code === 401) throw new PanelError('Сеанс роутера истёк. Войдите снова.', 401);
    return body;
  }
  async login(password) {
    const [page, info] = await Promise.all([this.request('/cgi-bin/luci/web'), this.api(null, 'xqsystem/init_info')]);
    if (+info.code !== 0 || info.hardware !== this.config.model) throw new PanelError('Панель рассчитана на Xiaomi BE6500 Pro / RD08.', 409);
    const key = page.match(/key:\s*'([^']+)'/)?.[1];
    const deviceId = page.match(/var deviceId = '([^']+)'/)?.[1];
    if (!key || !deviceId) throw new PanelError('Формат входа роутера изменился.', 502);
    const mode = +info.newEncryptMode === 1 ? 'sha256' : 'sha1';
    const nonce = `0_${deviceId}_${Math.floor(Date.now()/1000)}_${randomInt(10000)}`;
    const result = await this.api(null, 'xqsystem/login', 'POST', { username:'admin', password:digest(nonce + digest(password + key, mode), mode), nonce, logtype:'2' });
    if (+result.code !== 0 || !/^[a-f0-9]+$/i.test(result.token || '')) throw new PanelError('Не удалось войти. Проверьте пароль администратора.', 401);
    return { stok:result.token, info, touched:Date.now(), pending:new Map(), busy:false };
  }
  async logout(session) {
    try { await this.request(`/cgi-bin/luci/;stok=${session.stok}/web/logout`); } catch { /* Logout redirects in stock firmware. */ }
  }
  async preparePassword(oldPassword,newPassword){
    const [page,info]=await Promise.all([this.request('/cgi-bin/luci/web'),this.api(null,'xqsystem/init_info')]);
    const key=page.match(/key:\s*'([^']+)'/)?.[1],deviceId=page.match(/var deviceId = '([^']+)'/)?.[1];
    if(!key||!deviceId||info.hardware!==this.config.model)throw new PanelError('Формат смены пароля изменился.',502);
    const nonce=`0_${deviceId}_${Math.floor(Date.now()/1000)}_${randomInt(10000)}`;
    const encrypt=mode=>{const cipher=createCipheriv('aes-128-cbc',Buffer.from(digest(oldPassword+key,mode).slice(0,32),'hex'),Buffer.from('64175472480004614961023454661220','hex'));return Buffer.concat([cipher.update(digest(newPassword+key,mode),'utf8'),cipher.final()]).toString('base64');};
    const mode=+info.newEncryptMode===1?'sha256':'sha1';
    return {nonce,oldPwd:digest(nonce+digest(oldPassword+key,mode),mode),newPwd:encrypt('sha1'),newPwd256:encrypt('sha256')};
  }
  async backup(session, kind='config') {
    if(!['config','logs'].includes(kind))throw new PanelError('Неизвестный архив.');
    const result=checked(await this.api(session.stok,kind==='config'?'misystem/c_backup':'misystem/sys_log','GET',kind==='config'?{keys:'mi_basic_info,mi_wifi_info,mi_network_info,mi_lan_info,mi_arn_info'}:undefined));
    if(!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,180}\.(?:tar\.gz|tgz|gz)$/.test(result.file||'')||result.file.includes('..'))throw new PanelError('Неожиданное имя архива.',502);
    const bytes=await this.request(`/cgi-bin/luci/;stok=${session.stok}/api/misystem/c_download/${encodeURIComponent(result.file)}`,'GET',undefined,true);
    if(bytes[0]!==0x1f||bytes[1]!==0x8b)throw new PanelError('Роутер не вернул архив резервной копии.',502);
    return bytes;
  }
  async whitelistSession(stok,domain){
    domain=securityDomain(domain);
    const page=await this.request('/cgi-bin/luci/url_fw','GET',undefined,false,{host:domain,port:8900});
    const match=page.match(/data:\s*\{url:'([^']+)',\s*session:'([^']+)'\}/);
    if(match?.[1]!==domain||!match[2]||match[2]==='0'||!/^[a-zA-Z0-9_.:=-]{1,256}$/.test(match[2]))throw new PanelError('Штатная страница не выдала разрешение для этого исключения.',422);
    return match[2];
  }
  async uploadPlugin(stok,bytes){
    const inspection=inspectPluginPackage(bytes,{hardware:this.config.model,firmware:this.config.writeFirmware});
    if(!inspection.uploadable)throw new PanelError('Пакет не прошёл проверку совместимости и подписи.',422);
    return this.uploadImage(stok,'xqsystem/upload_plug',bytes);
  }
  async uploadImage(stok,route,bytes){
    if(!['xqsystem/upload_plug','xqsystem/upload_rom','misystem/c_upload'].includes(route))throw new PanelError('Неизвестный загрузчик.');
    const features=route==='misystem/c_upload'?null:checked(normalizeRead('misystem/feature_info',await this.api(stok,'misystem/feature_info')));
    const infile=String(features?.system?.infileupload)==='1',filename=route==='misystem/c_upload'?'cfg_backup.tar.gz':route==='xqsystem/upload_rom'?'firmware.bin':'plugin.mpk';
    const boundary='rd08-'+randomBytes(24).toString('hex');
    const body=Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`),bytes,Buffer.from(`\r\n--${boundary}--\r\n`)]);
    if(body.length>(infile?100*1024*1024:50*1024))throw new PanelError('Файл превышает лимит штатного маршрута загрузки (100 МиБ для infile или 50 КиБ для обычной формы).',413);
    const reply=await this.request(`${infile?'/uploadfile':''}/cgi-bin/luci/;stok=${stok}/api/${route}`,'POST',body,false,{contentType:'multipart/form-data; boundary='+boundary,timeoutMs:120000});
    try{return JSON.parse(reply);}catch{throw new PanelError('Загрузчик вернул неожиданный ответ. Проверьте каталог плагинов перед повторной попыткой.',502);}
  }
}
export function normalizeRead(route, value) {
  if(route==='misystem/feature_info'&&value&&typeof value==='object'&&!Array.isArray(value)&&value.code===undefined&&!value.error)value={...value,code:0};
  if(['config_scanner/overview','sec_center/overview'].includes(route)){
    const scanner=route==='sec_center/overview'?value.config_scanner:value;
    if(scanner?.wifi_passwd_secure&&typeof scanner.wifi_passwd_secure==='object'&&!Array.isArray(scanner.wifi_passwd_secure)){
      const {wifi_passwd_secure,...rest}=scanner;const normalized={...rest,wifiKeyStrength:wifi_passwd_secure};
      value=route==='sec_center/overview'?{...value,config_scanner:normalized}:normalized;
    }
  }
  // This getter returns the firewall setting in code, not an API status code.
  return route==='xqnetwork/get_ipv6_firewall'&&['0','1'].includes(String(value.code)) ? {code:0,mode:String(value.code)} : value;
}
const safeEqual = (a, b) => typeof a === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const ERRORS = { 1523:'Проверьте параметры настройки.', 1614:'Профиль этой службы недоступен.', 1604:'Проверьте адрес или данные подключения.', 1605:'Проверьте параметры подключения.' };
function checked(result) {
  if (+result.code !== 0) throw new PanelError(ERRORS[+result.code] || `Роутер отклонил настройку (код ${result.code}).`, 422);
  if (+result.need_confirm===1)throw new PanelError('Роутер запросил дополнительное подтверждение DFS/CAC. Изменение не подтверждено; обновите состояние перед повторной попыткой.',409);
  return result;
}
export async function createPanel({ config, router = new Router(config), port = config.port || 18650, demo = false } = {}) {
  const csrf = randomBytes(32).toString('hex'); const sessions = new Map();
  const nativeStages={firmware:null,restore:null};let nativeBusy=false;
  const origin = `http://127.0.0.1:${port}`; let failedLogins = [];
  const assets = new Map();
  for (const name of ['index.html','app.js','system-ui.js','utilities-ui.js','style.css']) assets.set('/'+(name === 'index.html' ? '' : name), await readFile(join(DIR,'public',name), 'utf8'));
  const security = { 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" };
  const send = (res,status,body,headers={}) => { res.writeHead(status,{...security,'Content-Type':'application/json; charset=utf-8',...headers});res.end(typeof body === 'string'||Buffer.isBuffer(body)?body:JSON.stringify(body)); };
  const expire = session => Date.now() - session.touched > 30*60*1000;
  const forget=session=>{session.miio?.close();session.pending.clear();session.pluginPackage=null;session.systemFile=null;session.systemStaged=null;};
  const server = http.createServer(async(req,res) => {
    try {
      if (req.headers.host !== `127.0.0.1:${port}` || (req.headers.origin && req.headers.origin !== origin) || req.headers['sec-fetch-site'] === 'cross-site') throw new PanelError('Запрос разрешён только из локальной панели.',403);
      const url = new URL(req.url, origin);
      if (req.method === 'GET' && assets.has(url.pathname)) {
        const type = url.pathname.endsWith('.js')?'application/javascript':url.pathname.endsWith('.css')?'text/css':'text/html';
        return send(res,200,assets.get(url.pathname).replace('__CSRF__',csrf),{'Content-Type':type+'; charset=utf-8'});
      }
      if (!url.pathname.startsWith('/api/')) throw new PanelError('Страница не найдена.',404);
      if (!safeEqual(req.headers['x-panel-csrf'],csrf)) throw new PanelError('Обновите страницу панели.',403);
      const sid = req.headers.cookie?.match(/(?:^|;\s*)rd08=([a-f0-9]{64})(?:;|$)/)?.[1];
      let session = sessions.get(sid);
      if(session && expire(session)) { forget(session);sessions.delete(sid);session=null; }
      let body = {},packageBytes;
      if (req.method === 'POST') {
        const packageUpload=url.pathname==='/api/plugin-package',systemUpload=url.pathname==='/api/system-file',binaryUpload=packageUpload||systemUpload;
        if(binaryUpload&&!session)throw new PanelError('Войдите в панель.',401);
        if(binaryUpload&&session.info.romversion!==config.writeFirmware)throw new PanelError('Загрузка файлов доступна для 1.1.123.',409);
        const kind=url.searchParams.get('kind');
        if(systemUpload&&!['firmware','restore'].includes(kind))throw new PanelError('Неизвестный тип файла.');
        if (!req.headers['content-type']?.startsWith(binaryUpload?'application/octet-stream':'application/json')) throw new PanelError(binaryUpload?'Нужен двоичный файл.':'Нужен JSON.',415);
        let size=0;const chunks=[];
        const limit=packageUpload?MAX_PLUGIN_BYTES:systemUpload?(kind==='firmware'?MAX_FIRMWARE_BYTES:MAX_BACKUP_BYTES):65536;
        for await (const chunk of req) { size+=chunk.length; if(size>limit)throw new PanelError('Слишком большой запрос.',413);chunks.push(chunk); }
        if(binaryUpload)packageBytes=Buffer.concat(chunks);
        else{
          try { body=JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new PanelError('Неверный JSON.'); }
          if(!body||typeof body!=='object'||Array.isArray(body))throw new PanelError('Нужен объект JSON.');
        }
      } else if (req.method !== 'GET') throw new PanelError('Метод недоступен.',405);
      if(url.pathname === '/api/info' && req.method === 'GET') {
        const info = session?.info || await router.api(null,'xqsystem/init_info');
        return send(res,200,{panelVersion:PANEL_VERSION,model:info.hardware,firmware:info.romversion,region:info.countrycode,authenticated:!!session,writeSupported:info.romversion === config.writeFirmware,routerHost:config.host,demo});
      }
      if(url.pathname === '/api/login' && req.method === 'POST') {
        failedLogins=failedLogins.filter(t=>Date.now()-t<60000);
        if(failedLogins.length>=3)throw new PanelError('Подождите минуту перед новой попыткой входа.',429);
        text(body.password,'Пароль',256);
        try { session=await router.login(body.password); } catch(e) { failedLogins.push(Date.now());throw e; }
        body.password=''; if(sid){const old=sessions.get(sid);if(old){forget(old);await router.logout(old);}sessions.delete(sid);}
        const nextId=randomBytes(32).toString('hex'); sessions.set(nextId,session);
        return send(res,200,{ok:true},{'Set-Cookie':`rd08=${nextId}; HttpOnly; SameSite=Strict; Path=/`});
      }
      if(!session)throw new PanelError('Войдите в панель.',401);
      session.touched=Date.now();
      if(url.pathname==='/api/miio-state'&&req.method==='GET')return send(res,200,session.miioState||null);
      if(url.pathname==='/api/miio-disconnect'&&req.method==='POST'){
        session.miio?.close();session.miio=null;session.miioState=null;session.pending.clear();return send(res,200,{ok:true});
      }
      if(['/api/miio-connect','/api/miio-read'].includes(url.pathname)&&req.method==='POST'){
        if(session.busy||nativeBusy)throw new PanelError('Дождитесь текущей операции.',409);
        if(session.info.romversion!==config.writeFirmware)throw new PanelError('Мост проверяется только для 1.1.123.',409);
        session.miioState=null;
        if(url.pathname==='/api/miio-connect'){
          session.miio?.close();session.miio=null;
          const token=text(body.token,'Собственный miIO-токен',32);
          if(!/^[a-f0-9]{32}$/i.test(token)||/^(?:0{32}|f{32})$/i.test(token))throw new PanelError('Токен устройства должен содержать 32 шестнадцатеричных символа и не быть пустым.');
          if(demo)throw new PanelError('В демонстрации miIO отключён: токены и команды не передаются реальному роутеру.',422);
          session.miio=new MiioLocal({host:config.host,token});body.token='';
        }
        if(!session.miio)throw new PanelError('Сначала подключите собственный токен устройства.',409);
        session.busy=true;try{
          const state=await session.miio.getState(),version=await session.miio.getVersion();
          session.miioState={...state,...version,at:Date.now()};return send(res,200,session.miioState);
        }catch(e){session.miio.close();session.miio=null;throw new PanelError('Локальный miIO-мост недоступен или отклонил токен/операцию. Состояние Bluetooth неизвестно.',422);}finally{session.busy=false;}
      }
      if(url.pathname==='/api/timezones'&&req.method==='GET')return send(res,200,TIMEZONES);
      if(url.pathname==='/api/system-file'&&req.method==='POST'){
        session.pending.clear();session.systemFile=null;
        const kind=url.searchParams.get('kind'),inspection=inspectSystemFile(packageBytes,kind,{hardware:config.model});
        if(inspection.valid)session.systemFile={kind,bytes:packageBytes,inspection,at:Date.now()};
        return send(res,200,inspection);
      }
      if(url.pathname==='/api/system-stage'&&req.method==='GET'){
        const stage=session.systemStaged;
        return send(res,200,stage&&Date.now()-stage.at<600000&&nativeStages[stage.kind]===stage.id?publicData(stage):null);
      }
      if(url.pathname==='/api/update-check'&&req.method==='POST'){
        if(session.info.romversion!==config.writeFirmware)throw new PanelError('Проверка доступна для 1.1.123.',409);
        const answer=checked(await router.api(session.stok,'xqsystem/check_rom_update'));
        session.update={at:Date.now(),info:answer};return send(res,200,publicData(answer));
      }
      if(url.pathname === '/api/logout' && req.method === 'POST') {
        sessions.delete(sid);forget(session);await router.logout(session);
        return send(res,200,{ok:true},{'Set-Cookie':'rd08=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
      }
      if(url.pathname==='/api/plugin-package'&&req.method==='POST'){
        session.pending.clear();session.pluginPackage=null;
        const inspection=inspectPluginPackage(packageBytes,{hardware:config.model,firmware:session.info.romversion});
        if(inspection.uploadable)session.pluginPackage={bytes:packageBytes,inspection,created:Date.now()};
        return send(res,200,inspection);
      }
      if(url.pathname==='/api/plugin-example'&&req.method==='GET')return send(res,200,await readFile(join(DIR,'examples','rd08-status.zip')),{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="RD08-plugin-source.zip"'});
      if(url.pathname === '/api/read' && req.method === 'GET') {
        const group=url.searchParams.get('group');if(!Object.hasOwn(GROUPS,group))throw new PanelError('Нет такого раздела.',404);const routes=GROUPS[group];
        const result={};
        // Two requests at a time keeps stock LuCI responsive while another client uses it.
        const entries=Object.entries(routes);
        for(let i=0;i<entries.length;i+=2)await Promise.all(entries.slice(i,i+2).map(async([key,route])=>{
          try{const answer=normalizeRead(route,await router.api(session.stok,route,'GET',READ_PARAMS[route]));if(+answer.code===401)throw new PanelError('Сеанс истёк.',401);result[key]=publicData(answer);}catch(e){if(e.status===401)throw e;result[key]={code:-1,error:'API недоступен или не поддерживается этой конфигурацией.'};}
        }));
        return send(res,200,result);
      }
      if(url.pathname==='/api/iot-device'&&req.method==='GET'){
        const address=mac(url.searchParams.get('mac'));
        const devices=checked(await router.api(session.stok,'misystem/devicelist')).list||[];
        if(!devices.some(d=>String(d.mac).toUpperCase()===address))throw new PanelError('Устройства больше нет в списке.',404);
        const result={};for(const[key,route]of Object.entries({trusted:'device_security/get_trusted',blocked:'device_security/get_blocked',status:'device_security/device_status'}))result[key]=publicData(checked(await router.api(session.stok,route,'GET',{mac:address})));
        return send(res,200,result);
      }
      if(url.pathname==='/api/mesh-binding'&&req.method==='GET'){
        const address=mac(url.searchParams.get('mac')),devices=checked(await router.api(session.stok,'misystem/devicelist')).list||[];
        if(!devices.some(d=>String(d.mac).toUpperCase()===address))throw new PanelError('Клиента больше нет в списке.',404);
        return send(res,200,publicData(checked(await router.api(session.stok,'xqnetwork/get_sta_bindinfo','GET',{sta_mac:address}))));
      }
      if(url.pathname==='/api/mesh-discovery'&&req.method==='GET')return send(res,200,{...(session.meshDiscovery?publicData(session.meshDiscovery.result):{code:0,list:[]}),age:session.meshDiscovery?Math.floor((Date.now()-session.meshDiscovery.at)/1000):null,addingMac:session.meshAddingMac||null});
      if(url.pathname==='/api/mesh-add-status'&&req.method==='GET'){
        if(!session.meshAddingMac)throw new PanelError('В этом сеансе узел ещё не добавлялся.',409);
        return send(res,200,publicData(checked(await router.api(session.stok,'xqnetwork/get_addnode_status','GET',{mac:session.meshAddingMac}))));
      }
      if(url.pathname==='/api/logs'&&req.method==='GET'){
        const params=logQuery(Object.fromEntries(url.searchParams));
        const answer=checked(await router.api(session.stok,'mi_log/get_logs','GET',params));
        session.logPage={params,ids:(answer.info||[]).flatMap(day=>(day.data||[]).map(row=>String(row.id))).filter(id=>/^\d+$/.test(id))};
        return send(res,200,publicData(answer));
      }
      if(url.pathname==='/api/scanner'&&req.method==='POST'){
        if(!['start','status','stop'].includes(body.op))throw new PanelError('Неизвестная операция проверки.');
        if(body.op!=='status'&&session.info.romversion!==config.writeFirmware)throw new PanelError('Запуск проверки доступен для 1.1.123.',409);
        if(body.op==='start'){
          if(session.scanWorkId){const status=await router.api(session.stok,'config_scanner/get_status','GET',{work_id:session.scanWorkId});if(+status.code===0&&+status.meta?.status!==2)throw new PanelError('Проверка уже выполняется.',409);}
          const answer=checked(await router.api(session.stok,'config_scanner/start','POST',{})),id=answer.meta?.work_id;
          if(!/^[a-zA-Z0-9_-]{1,100}$/.test(String(id||'')))throw new PanelError('Роутер не вернул идентификатор проверки.',502);
          session.scanWorkId=String(id);return send(res,200,publicData(answer));
        }
        if(!session.scanWorkId)throw new PanelError('В этом сеансе проверка ещё не запускалась.',409);
        const answer=checked(await router.api(session.stok,body.op==='stop'?'config_scanner/stop':'config_scanner/get_status',body.op==='stop'?'POST':'GET',{work_id:session.scanWorkId}));
        return send(res,200,publicData(normalizeRead('config_scanner/overview',answer)));
      }
      if(url.pathname==='/api/backup'&&req.method==='POST'){
        if(session.info.romversion!==config.writeFirmware)throw new PanelError('Архивирование доступно для 1.1.123.',409);
        if(session.busy)throw new PanelError('Дождитесь текущей операции.',409);
        session.busy=true;
        const kind=body.kind??'config';if(!['config','logs'].includes(kind)){session.busy=false;throw new PanelError('Неизвестный архив.');}
        try{return send(res,200,await router.backup(session,kind),{'Content-Type':'application/gzip','Content-Disposition':`attachment; filename="RD08-${kind}.tar.gz"`});}finally{session.busy=false;}
      }
      if(url.pathname==='/api/last-change'&&req.method==='GET')return send(res,200,session.lastBefore||{});
      if(url.pathname==='/api/detail'&&req.method==='GET'){
        if(url.searchParams.get('kind')!=='parental')throw new PanelError('Нет такого вида данных.',404);
        const id=url.searchParams.get('user_id');if(!/^[1-9]\d{0,9}$/.test(id||'')||+id>2147483647)throw new PanelError('Неверный профиль.');
        const users=checked(await router.api(session.stok,'misystem/mipctl_get_user_list')).user_list||[];
        if(!users.some(u=>String(u.user_id)===id))throw new PanelError('Профиль больше не существует.',404);
        const result={};
        for(const [key,route]of Object.entries({hosts:'misystem/mipctl_get_filting_net',schedule:'misystem/mipctl_get_deny_time',pause:'misystem/mipctl_get_temp_deny',apps:'misystem/mipctl_get_app_antiaddict',allow:'misystem/mipctl_get_temp_allow'})){
          try{result[key]=publicData(checked(await router.api(session.stok,route,'GET',{user_id:id})));}catch(e){if(e.status===401)throw e;result[key]={code:-1,error:'Правила недоступны.'};}
        }
        const assignments=checked(await router.api(session.stok,'misystem/mipctl_get_device_list'));
        result.devices=assignments.list?.find(x=>String(x.user_id)===id)?.devices||[];
        return send(res,200,result);
      }
      if(url.pathname === '/api/preview' && req.method === 'POST') {
        if(session.info.romversion !== config.writeFirmware)throw new PanelError('Запись проверена для 1.1.123. Для другой версии доступно только чтение.',409);
        if(body.action==='bleEnable'){
          if(!session.miio||!session.miioState||typeof session.miioState.enabled!=='boolean')throw new PanelError('Сначала подключите miIO-токен и прочитайте состояние шлюза.',409);
          if(!['0','1'].includes(String(body.data?.on)))throw new PanelError('Недопустимое состояние шлюза.');
          const enabled=String(body.data.on)==='1',ticket=randomBytes(24).toString('hex'),changes=[{label:'Bluetooth Mesh шлюз',value:enabled?'Включить':'Выключить'}],notice='Изменится работа Bluetooth-шлюза и связанных умных устройств. Работа через miIO зависит от политики доступа этой прошивки.';
          session.pending.clear();session.pending.set(ticket,{kind:'bleEnable',miio:session.miio,enabled,changes,notice,before:{enabled:session.miioState.enabled},created:Date.now()});return send(res,200,{ticket,changes,notice,before:{enabled:session.miioState.enabled},wait:0});
        }
        if(body.action==='systemFileStage'){
          const file=session.systemFile;
          if(!file||Date.now()-file.at>600000||body.data?.sha256!==file.inspection.sha256)throw new PanelError('Проверенный файл устарел. Выберите его снова.',409);
          const ticket=randomBytes(24).toString('hex');session.pending.clear();
          const changes=[{label:'Передать штатному загрузчику',value:file.kind==='firmware'?'Файл прошивки':'Архив конфигурации'},{label:'SHA-256',value:file.inspection.sha256}];
          const notice=file.kind==='firmware'?'Передача ещё не записывает прошивку, но штатный загрузчик останавливает плагины ДО проверки образа. Это может прервать их работу. После передачи потребуется отдельное подтверждение установки.':'Архив будет передан и проверен штатным загрузчиком. Настройки пока не применяются. Для восстановления потребуется выбрать разделы и подтвердить действие.';
          session.pending.set(ticket,{kind:'systemFileStage',file,changes,notice,before:{},created:Date.now()});return send(res,200,{ticket,changes,notice,before:{},wait:0});
        }
        if(body.action==='adminPassword'){
          const oldPassword=text(body.data?.oldPassword,'Текущий пароль',256),newPassword=text(body.data?.newPassword,'Новый пароль',63);
          if(Buffer.byteLength(newPassword)<8||Buffer.byteLength(newPassword)>63||newPassword!==body.data?.repeatPassword)throw new PanelError('Новый пароль: 8–63 байта; повтор должен совпадать.');
          if(oldPassword===newPassword)throw new PanelError('Новый пароль совпадает с текущим.');
          const params=await router.preparePassword(oldPassword,newPassword);body.data={};
          const ticket=randomBytes(24).toString('hex'),changes=[{label:'Пароль администратора',value:'Заменить и завершить сеансы панели'}],notice='После сохранения войдите с новым паролем. Сеансы, открытые вне этой панели, штатный API может сохранить.';
          session.pending.clear();session.pending.set(ticket,{kind:'adminPassword',steps:[{path:'xqsystem/set_name_password',method:'POST',params}],changes,notice,before:{},reauth:true,created:Date.now(),message:'Пароль изменён. Войдите с новым паролем.'});
          return send(res,200,{ticket,changes,notice,before:{},wait:0});
        }
        if(body.action==='pluginInstall'){
          const pkg=session.pluginPackage;
          if(!pkg||Date.now()-pkg.created>600000||body.data?.sha256!==pkg.inspection.sha256)throw new PanelError('Проверенный пакет устарел. Выберите файл снова.',409);
          const ticket=randomBytes(24).toString('hex');session.pending.clear();
          const changes=[{label:'Установить пакет',value:pkg.inspection.inner.manifest.name},{label:'Версия',value:pkg.inspection.inner.manifest.version},{label:'SHA-256',value:pkg.inspection.sha256}];
          const notice='Файл будет передан штатному загрузчику Xiaomi. Установка выполняет код плагина и может изменить работу роутера. Подпись подтверждает источник, а не безвредность программы.';
          session.pending.set(ticket,{kind:'pluginInstall',package:pkg,steps:[],changes,notice,before:{},created:Date.now()});return send(res,200,{ticket,changes,notice,before:{},wait:5});
        }
        const context={};for(const path of Object.hasOwn(CONTEXT,body.action)?CONTEXT[body.action]:[])context[path]=checked(normalizeRead(path,await router.api(session.stok,path,'GET',READ_PARAMS[path])));
        if(body.action==='iotTrusted'||body.action==='iotMark'){
          const address=mac(body.data?.mac);if(!context['misystem/devicelist']?.list?.some(d=>String(d.mac).toUpperCase()===address))throw new PanelError('Устройства нет в текущем списке.');
          for(const route of ['device_security/get_trusted','device_security/get_blocked'])context[route]=checked(await router.api(session.stok,route,'GET',{mac:address}));
        }
        if(body.action==='urlWhitelistAdd')context['panel/whitelistSession']={session:await router.whitelistSession(session.stok,securityDomain(body.data?.url))};
        if(body.action==='logDelete')context['panel/logPage']=session.logPage;
        if(body.action==='onlineUpgrade')context['panel/update']=session.update;
        if(['firmwareFlash','restoreApply'].includes(body.action)){
          const stage=session.systemStaged;
          if(!stage||nativeStages[stage.kind]!==stage.id)throw new PanelError('Подготовленный файл заменён. Передайте его снова.',409);
          context['panel/systemStaged']=stage;
        }
        if(body.action==='meshBind'){
          const address=mac(body.data?.mac);context['xqnetwork/get_sta_bindinfo']=checked(await router.api(session.stok,'xqnetwork/get_sta_bindinfo','GET',{sta_mac:address}));context.meshBindingMac=address;
        }
        if(body.action==='meshAdd')context.meshDiscovery=session.meshDiscovery;
        if(body.action==='pppoeLink'&&body.data?.wan==='WAN2')context['xqnetwork/wan_info:WAN2']=checked(await router.api(session.stok,'xqnetwork/wan_info','GET',{wan_name:'WAN2'}));
        if(body.action==='parentalApps'||body.action==='parentalAllow'){
          const id=String(body.data?.user_id||'');if(!/^[1-9]\d{0,9}$/.test(id))throw new PanelError('Неверный профиль.');
          const route=body.action==='parentalApps'?'misystem/mipctl_get_app_antiaddict':'misystem/mipctl_get_temp_allow';context[route]=checked(await router.api(session.stok,route,'GET',{user_id:id}));
        }
        if(['parentalSchedule','parentalHosts','parentalPause','parentalDevices','parentalDelete'].includes(body.action)){
          if(!/^[1-9]\d{0,9}$/.test(String(body.data?.user_id||'')))throw new PanelError('Неверный профиль.');
          const extra={parentalSchedule:['misystem/mipctl_get_deny_time'],parentalHosts:['misystem/mipctl_get_filting_net'],parentalPause:['misystem/mipctl_get_temp_deny'],parentalDevices:[],parentalDelete:['misystem/mipctl_get_deny_time','misystem/mipctl_get_filting_net','misystem/mipctl_get_temp_deny']}[body.action];
          for(const route of extra)context[route]=checked(await router.api(session.stok,route,'GET',{user_id:String(body.data.user_id)}));
          context['misystem/mipctl_get_device_list']=checked(await router.api(session.stok,'misystem/mipctl_get_device_list'));
          context['xqsystem/device_mac']=checked(await router.api(session.stok,'xqsystem/device_mac'));
        }
        const plan=buildUtilityPlan(body.action,body.data,context)??buildSystemPlan(body.action,body.data,context)??buildSecurityPlan(body.action,body.data,context)??buildNetworkPlan(body.action,body.data,context)??buildPlan(body.action,body.data,context);const ticket=randomBytes(24).toString('hex');session.pending.clear();const before=publicData(context);session.pending.set(ticket,{...plan,...(context['panel/systemStaged']?{stage:context['panel/systemStaged']} :{}),before,created:Date.now()});
        return send(res,200,{ticket,changes:plan.changes,notice:plan.notice,wait:plan.wait,before});
      }
      if(url.pathname === '/api/apply' && req.method === 'POST') {
        const plan=session.pending.get(body.ticket);
        if(!plan||Date.now()-plan.created>120000)throw new PanelError('Предпросмотр устарел. Откройте его снова.',409);
        if(session.busy||nativeBusy)throw new PanelError('Дождитесь завершения предыдущей настройки.',409);
        if(plan.stage&&(nativeStages[plan.stage.kind]!==plan.stage.id||Date.now()-plan.stage.at>=600000))throw new PanelError('Подготовленный файл заменён или устарел.',409);
        session.pending.delete(body.ticket);session.busy=true;nativeBusy=true;session.lastBefore={time:new Date().toISOString(),changes:plan.changes,before:plan.before};
        let completed=0,wait=plan.wait,output;
        try{
          if(plan.kind==='bleEnable'){
            if(!session.miio||session.miio!==plan.miio)throw new PanelError('Подключение miIO изменилось. Подготовьте действие снова.',409);
            session.miioState=null;let answer;try{answer=await session.miio.setEnabled(plan.enabled);}catch{throw new PanelError('Изменение шлюза не подтверждено. Прочитайте состояние перед повторной попыткой.',422);}session.miioState={...answer,at:Date.now()};return send(res,200,{ok:true,wait:0,message:'Состояние Bluetooth-шлюза подтверждено повторным чтением.'});
          }
          if(plan.stage){nativeStages[plan.stage.kind]=null;session.systemStaged=null;}
          if(plan.kind==='systemFileStage'){
            const file=plan.file;session.systemFile=null;nativeStages[file.kind]=null;session.systemStaged=null;
            if(Date.now()-file.at>=600000||digest(file.bytes,'sha256')!==file.inspection.sha256)throw new PanelError('Файл устарел. Проверьте его снова.',409);
            const reply=checked(await router.uploadImage(session.stok,file.kind==='firmware'?'xqsystem/upload_rom':'misystem/c_upload',file.bytes));
            const id=randomBytes(24).toString('hex');nativeStages[file.kind]=id;session.systemStaged={id,kind:file.kind,at:Date.now(),inspection:file.inspection,reply};
            return send(res,200,{ok:true,wait:0,message:'Файл принят штатным загрузчиком. Выберите следующий шаг в разделе «Система».',stage:publicData(session.systemStaged)});
          }
          if(plan.kind==='pluginInstall'){
            checked(await router.uploadPlugin(session.stok,plan.package.bytes));session.pluginPackage=null;
            return send(res,200,{ok:true,wait:5,message:'Пакет принят штатным загрузчиком. Проверьте статус установки в каталоге.'});
          }
          for(const step of plan.steps){const answer=checked(await router.api(session.stok,step.path,step.method,step.params));const cac=Number(answer.cac_time);if(Number.isFinite(cac)&&cac>wait&&cac<=1800)wait=cac+10;if(step.path==='xqnetwork/scan_mesh_node'){session.meshDiscovery={at:Date.now(),result:answer};output=publicData(answer);}if(step.path==='xqnetwork/add_mesh_node')session.meshAddingMac=step.params.mac;completed++;}
          for(const check of plan.checks||[])if(check.kind==='urlWhitelist'){
            const answer=checked(await router.api(session.stok,'url_fw/show_whitelist'));
            if(!answer.whitelist?.some(x=>x.url===check.url))throw new PanelError('Роутер не подтвердил добавление исключения. Обновите список.',422);
          }
          if(plan.reauth){
            const owned=[...sessions.values()];
            for(const s of owned){forget(s);await router.logout(s);}
            sessions.clear();
          }
          return send(res,200,{ok:true,wait,reauth:!!plan.reauth,...(plan.message?{message:plan.message}:{}),...(output?{output}:{})},plan.reauth?{'Set-Cookie':'rd08=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}:{});
        }catch(e){if(completed)e.message='Часть настройки уже сохранена. Обновите данные перед повторной попыткой. '+e.message;throw e;}
        finally{session.busy=false;nativeBusy=false;}
      }
      throw new PanelError('Операция не найдена.',404);
    }catch(e){send(res,e.status||500,{error:e instanceof PanelError?e.message:'Ошибка локальной панели. Перезапустите приложение.'});}
  });
  server.requestTimeout=120000;server.headersTimeout=10000;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
  const cleanup=setInterval(()=>{for(const[id,s]of sessions){if(expire(s)){forget(s);sessions.delete(id);continue;}for(const[t,p]of s.pending)if(Date.now()-p.created>120000)s.pending.delete(t);if(s.pluginPackage&&Date.now()-s.pluginPackage.created>600000)s.pluginPackage=null;if(s.systemFile&&Date.now()-s.systemFile.at>600000)s.systemFile=null;}},60000);cleanup.unref();server.on('close',()=>{clearInterval(cleanup);for(const s of sessions.values())forget(s);sessions.clear();});
  return {server,origin};
}
if(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config=JSON.parse(await readFile(join(DIR,'router-config.json'),'utf8'));
  try{const {origin}=await createPanel({config});console.log(`Router Panel ready: ${origin}`);}
  catch(e){if(e.code==='EADDRINUSE')console.log(`Router Panel is already available: http://127.0.0.1:${config.port}`);else{console.error('Не удалось запустить панель. Проверьте router-config.json и Node.js.');process.exitCode=1;}}
}
