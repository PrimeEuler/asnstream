'use strict';
/* Round-trip tests for asnstream. Run: node test/test.js */
const assert = require('node:assert');
const path = require('node:path');
const { PassThrough } = require('node:stream');

const asnstream = require('../src/index.js');
const { MibRegistry } = asnstream;
const { encodeMessage, decodeMessage } = asnstream;
const { encodeFrame, FrameDecoder } = asnstream;
const { MessageEncoder, MessageDecoder } = asnstream;

const MIBDIR = path.join(__dirname, '..', '..', 'asn2json', 'SMI', 'MIB');
const mib = (f) => path.join(MIBDIR, f);

function registry() {
  return asnstream.loadMibs(mib('RFC1155-SMI.mib'), mib('RFC-1212.mib'), mib('RFC1213-MIB-II.mib'));
}

const row = (i) => ({
  ifIndex: i,
  ifDescr: `eth${i}`,
  ifType: 6,
  ifMtu: 1500,
  ifSpeed: 1000000000,
  ifPhysAddress: Buffer.from([0x02, 0x42, 0xac, 0x11, 0x00, 0x0a + i]),
  ifAdminStatus: 1,
  ifOperStatus: 1,
  ifLastChange: 123456,
  ifInOctets: 4294967000 + i,
  ifInUcastPkts: 1000 + i,
  ifInNUcastPkts: 0,
  ifInDiscards: 0,
  ifInErrors: 0,
  ifInUnknownProtos: 0,
  ifOutOctets: 2000 + i,
  ifOutUcastPkts: 500 + i,
  ifOutNUcastPkts: 0,
  ifOutDiscards: 0,
  ifOutErrors: 0,
  ifOutQLen: 0,
  ifSpecific: '0.0',
});

async function main() {
  const reg = registry();

  // 1. OID resolution through the SMI tree
  assert.strictEqual(reg.oidOf('ifDescr'), '1.3.6.1.2.1.2.2.1.2');
  assert.strictEqual(reg.oidOf('ifEntry'), '1.3.6.1.2.1.2.2.1');
  assert.strictEqual(reg.oidOf('sysDescr'), '1.3.6.1.2.1.1.1');
  assert.strictEqual(reg.typeOfOid('1.3.6.1.2.1.2.2.1'), 'IfEntry');
  console.log('ok 1 - OID tree resolution');

  // 2. BER round trip of a full IfEntry row (app tags, DisplayString, OID)
  const ber = encodeMessage(reg, 'IfEntry', row(1));
  assert.ok(ber[0] === 0x30, 'SEQUENCE tag');
  const back = decodeMessage(reg, 'IfEntry', ber);
  assert.strictEqual(back.ifIndex, 1);
  assert.strictEqual(back.ifDescr, 'eth1');
  assert.strictEqual(back.ifSpeed, 1000000000);
  assert.strictEqual(back.ifInOctets, 4294967001);
  assert.ok(Buffer.isBuffer(back.ifPhysAddress));
  assert.strictEqual(back.ifSpecific, '0.0');
  // app tag check: find 0x41 (APPLICATION 1 = Counter) in the encoding
  assert.ok(ber.includes(0x41), 'Counter encoded with APPLICATION 1 tag');
  assert.ok(ber.includes(0x42), 'Gauge encoded with APPLICATION 2 tag');
  assert.ok(ber.includes(0x43), 'TimeTicks encoded with APPLICATION 3 tag');
  console.log('ok 2 - IfEntry BER round trip with SMI application tags');

  // 3. Frame round trip + incremental splitter with torn chunks
  const frame = encodeFrame(reg.oidOf('ifEntry'), ber);
  assert.strictEqual(frame.readUInt32BE(0), frame.length - 4);
  const splitter = new FrameDecoder();
  const parts = [];
  for (let i = 0; i < frame.length; i += 7) parts.push(splitter.push(frame.subarray(i, i + 7)));
  const frames = parts.flat();
  assert.strictEqual(frames.length, 1);
  assert.strictEqual(frames[0].oid, '1.3.6.1.2.1.2.2.1');
  assert.deepStrictEqual(frames[0].payload, ber);
  console.log('ok 3 - OID-tagged framing, torn-chunk reassembly');

  // 4. Stream pair over 1-byte chunks
  await new Promise((resolve, reject) => {
    const enc = new MessageEncoder(reg);
    const dec = new MessageDecoder(reg);
    const wire = new PassThrough();
    const got = [];
    enc.pipe(wire).pipe(dec);
    dec.on('data', (m) => {
      got.push(m);
      if (got.length === 2) {
        try {
          assert.strictEqual(got[0].type, 'IfEntry');
          assert.strictEqual(got[0].value.ifDescr, 'eth1');
          assert.strictEqual(got[1].value.ifIndex, 2);
          console.log('ok 4 - stream encode/decode');
          resolve();
        } catch (e) { reject(e); }
      }
    });
    dec.on('error', reject); enc.on('error', reject);
    const buf = Buffer.concat([encodeFrame(reg.oidOf('ifEntry'), encodeMessage(reg, 'IfEntry', row(1))),
                               encodeFrame(reg.oidOf('ifEntry'), encodeMessage(reg, 'IfEntry', row(2)))]);
    // feed one byte at a time to prove partial-frame handling
    let i = 0;
    const tick = () => {
      if (i >= buf.length) return;
      wire.write(buf.subarray(i, ++i));
      setImmediate(tick);
    };
    tick();
  });

  // 5. TCP loopback, multiplexed with a scalar object
  await new Promise((resolve, reject) => {
    const server = asnstream.tcp.serve(reg, 11024, ({ encoder }) => {
      encoder.write({ type: 'IfEntry', value: row(3) });
      encoder.write({ oid: reg.oidOf('sysDescr'), value: 'asnstream demo agent' });
    });
    server.on('listening', async () => {
      try {
        const link = await asnstream.tcp.connect(reg, 11024);
        const got = [];
        link.decoder.on('data', (m) => {
          got.push(m);
          if (got.length === 2) {
            assert.strictEqual(got[0].type, 'IfEntry');
            assert.strictEqual(got[0].value.ifIndex, 3);
            assert.strictEqual(got[1].oid, '1.3.6.1.2.1.1.1');
            assert.strictEqual(got[1].value, 'asnstream demo agent');
            console.log('ok 5 - TCP loopback, multiplexed row + scalar');
            link.socket.destroy();
            server.close(() => resolve());
          }
        });
        link.decoder.on('error', reject);
      } catch (e) { reject(e); }
    });
    server.on('error', reject);
  });

  // 6. Unknown OID passes through raw instead of dying
  await new Promise((resolve, reject) => {
    const enc = new MessageEncoder(reg);
    const dec = new MessageDecoder(reg);
    enc.pipe(dec);
    dec.on('data', (m) => {
      try {
        assert.strictEqual(m.oid, '1.3.6.1.4.1.99999');
        assert.strictEqual(m.type, null);
        assert.ok(Buffer.isBuffer(m.raw));
        console.log('ok 6 - unknown-OID passthrough');
        resolve();
      } catch (e) { reject(e); }
    });
    enc.write({ oid: '1.3.6.1.4.1.99999', type: 'INTEGER', value: 42 });
  });

  console.log('\nAll asnstream tests passed.');
}

main().catch((e) => { console.error('FAIL:', e); process.exit(1); });
