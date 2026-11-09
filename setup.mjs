import tls from 'node:tls';
import {isIP} from 'node:net';
import {writeFile} from 'node:fs/promises';
import {createInterface} from 'node:readline/promises';
import {pathToFileURL} from 'node:url';

export function validateHost(host) {
  if(isIP(host)!==4 || !/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host))
    throw new Error('Введите локальный IPv4-адрес роутера.');
  return host;
}

export function readFingerprint(host, port=443) {
  validateHost(host);
  return new Promise((resolve,reject)=>{
    // No credentials or HTTP requests are sent before the user verifies the certificate.
    const socket=tls.connect({host,port,rejectUnauthorized:false},()=>{
      const fingerprint=socket.getPeerCertificate().fingerprint256;
      socket.destroy();
      if(!/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(fingerprint||''))reject(new Error('Роутер не предоставил сертификат SHA-256.'));
      else resolve(fingerprint);
    });
    socket.setTimeout(8000,()=>socket.destroy(new Error('Нет ответа от роутера по HTTPS.')));
    socket.on('error',()=>reject(new Error('Не удалось прочитать сертификат роутера. Проверьте адрес и подключение.')));
  });
}

async function setup() {
  const input=createInterface({input:process.stdin,output:process.stdout});
  try {
    const host=validateHost((await input.question('Адрес роутера [192.168.31.1]: ')).trim()||'192.168.31.1');
    const httpsFingerprint256=await readFingerprint(host);
    console.log(`SHA-256 сертификата: ${httpsFingerprint256}`);
    console.log(`Откройте https://${host}, просмотрите сертификат в браузере и сравните отпечаток SHA-256.`);
    const confirmed=await input.question('Если отпечатки совпадают, введите ДОВЕРЯЮ: ');
    if(confirmed.trim()!=='ДОВЕРЯЮ')throw new Error('Настройка отменена. Конфигурация не сохранена.');
    await writeFile(new URL('./router-config.json',import.meta.url),JSON.stringify({host,httpsFingerprint256,model:'RD08',writeFirmware:'1.1.123',port:18650},null,2)+'\n',{flag:'wx',mode:0o600});
    console.log('Конфигурация сохранена. Запустите Start.cmd или npm start.');
  } finally {input.close();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {await setup();}
  catch(error) {
    console.error(error.code==='EEXIST'?'router-config.json уже существует. Для повторной настройки переименуйте его и запустите настройку снова.':error.message);
    process.exitCode=1;
  }
}
