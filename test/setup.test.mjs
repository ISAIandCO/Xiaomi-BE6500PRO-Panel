import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {validateHost,readFingerprint} from '../setup.mjs';

test('setup accepts private IPv4 only, before any connection',async()=>{
  for(const host of ['192.168.31.1','10.0.0.1','172.16.0.1','172.31.255.254'])assert.equal(validateHost(host),host);
  for(const host of ['192.168.999.1','127.0.0.1','8.8.8.8','172.32.0.1','example.net','::1','192.168.31.1/path']) {
    assert.throws(()=>validateHost(host),/IPv4/);
    assert.throws(()=>readFingerprint(host),/IPv4/);
  }
});

test('setup fails on a non-TLS peer without sending application data',async t=>{
  let received=Buffer.alloc(0);
  const server=net.createServer(socket=>socket.on('data',chunk=>{received=Buffer.concat([received,chunk]);socket.end('not TLS');}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  // Private IPv4 validation is tested above; use a local peer by mapping the outbound socket in this test.
  const {default:tls}=await import('node:tls');
  const original=tls.connect;
  t.mock.method(tls,'connect',(options,callback)=>original({...options,host:'127.0.0.1'},callback));
  await assert.rejects(readFingerprint('192.168.31.1',server.address().port),/сертификат/);
  assert(!received.includes(Buffer.from('password')));
  assert(!received.includes(Buffer.from('GET ')));
});
