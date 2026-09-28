'use strict';
/* Live-proxy tests: getters subscribe, setters publish, ACCESS enforced.
 * Run: node test/proxy.js */
const assert = require('node:assert');
const path = require('node:path');
const { PassThrough } = require('node:stream');

const asnstream = require('../src/index.js');
const { MessageEncoder, MessageDecoder } = asnstream;
const { marshal, unmarshal, linkFromStreams } = asnstream;

const MIBDIR = path.join(__dirname, '..', '..', 'asn2json', 'SMI', 'MIB');
const mib = (f) => path.join(MIBDIR, f);

function registry() {
  return asnstream.loadMibs(mib('RFC1155-SMI.mib'), mib('RFC-1212.mib'), mib('RFC1213-MIB-II.mib'));
}

const row = (i, admin = 1) => ({
  ifIndex: i,
  ifDescr: `eth${i}`,
  ifType: 6,
  ifMtu: 1500,
  ifSpeed: 1000000000,
  ifPhysAddress: Buffer.from([0x02, 0x42, 0xac, 0x11, 0x00, 0x0a + i]),
  ifAdminStatus: admin,
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

/** Full-duplex in-memory link pair through the real encoder/decoder. */
function duplexPair(reg) {
  const a2b = new PassThrough();
  const b2a = new PassThrough();
  const encA = new MessageEncoder(reg);
  const decA = new MessageDecoder(reg);
  const encB = new MessageEncoder(reg);
  const decB = new MessageDecoder(reg);
  encA.pipe(a2b).pipe(decB);
  encB.pipe(b2a).pipe(decA);
  for (const s of [encA, decA, encB, decB, a2b, b2a]) s.on('error', () => {});
  return { linkA: linkFromStreams(encA, decA), linkB: linkFromStreams(encB, decB) };
}

function once(emitter, ev) {
  return new Promise((resolve) => emitter.once(ev, (...a) => resolve(a)));
}

async function main() {
  const reg = registry();
  const { linkA, linkB } = duplexPair(reg);

  // 1. Value proxy: setter publishes, remote getter reads last-known.
  const contactA = marshal(reg, 'sysContact', linkA); // read-write scalar
  const contactB = marshal(reg, 'sysContact', linkB);
  const gotB = once(contactB, 'update');
  contactA.value = 'Jeremy <sysop@mesh>';
  const [valB] = await gotB;
  assert.strictEqual(valB, 'Jeremy <sysop@mesh>');
  assert.strictEqual(contactB.value, 'Jeremy <sysop@mesh>');
  console.log('ok 1 - value proxy: setter publishes, getter reads last-known');

  // 2. ACCESS: sysDescr is read-only, the setter throws.
  const descr = marshal(reg, 'sysDescr', linkA);
  assert.throws(() => { descr.value = 'x'; }, /not writable \(ACCESS read-only\)/);
  assert.strictEqual(descr.value, undefined); // never received, still unknown
  console.log('ok 2 - ACCESS enforced: read-only setter throws');

  // 3. Table proxy: agent publishes rows, manager materializes them.
  const agentT = marshal(reg, 'ifEntry', linkA);
  const mgrT = marshal(reg, 'ifEntry', linkB);
  const seenRows = new Promise((resolve) => {
    const acc = [];
    mgrT.on('row', (rp) => { acc.push(rp); if (acc.length === 2) resolve(acc); });
  });
  agentT.publish(row(1));
  agentT.publish(row(2));
  await seenRows;
  assert.strictEqual(mgrT.get(1).ifDescr, 'eth1');
  assert.strictEqual(mgrT.get(2).ifIndex, 2);
  assert.ok(mgrT.has(1));
  assert.ok(!mgrT.has(99));
  assert.strictEqual(mgrT.get(99).ifDescr, undefined); // placeholder, not yet seen
  console.log('ok 3 - table proxy materializes rows from the stream');

  // 4. Row column setter publishes a full-row update; column ACCESS enforced.
  const agentUpdate = once(agentT, 'update');
  mgrT.get(1).ifAdminStatus = 2; // read-write column: ok
  const [key, rp] = await agentUpdate;
  assert.strictEqual(key, '1');
  assert.strictEqual(rp.ifAdminStatus, 2);
  assert.strictEqual(agentT.get(1).ifAdminStatus, 2);
  assert.strictEqual(mgrT.get(1).ifAdminStatus, 2); // optimistic local apply
  assert.throws(() => { mgrT.get(1).ifDescr = 'nope'; }, /not writable \(ACCESS read-only\)/);
  assert.throws(() => { mgrT.get(99).ifAdminStatus = 2; }, /not present/);
  console.log('ok 4 - row column set publishes; column ACCESS + row-existence enforced');

  // 5. unmarshal snapshots are plain and detached (Buffers survive).
  const snap = unmarshal(mgrT);
  assert.strictEqual(snap['1'].ifDescr, 'eth1');
  assert.strictEqual(snap['1'].ifAdminStatus, 2);
  assert.ok(Buffer.isBuffer(snap['1'].ifPhysAddress));
  snap['1'].ifDescr = 'mutated';
  assert.strictEqual(mgrT.get(1).ifDescr, 'eth1');
  assert.strictEqual(unmarshal(contactA), 'Jeremy <sysop@mesh>');
  assert.strictEqual(unmarshal(mgrT.get(99)), null);
  console.log('ok 5 - unmarshal returns detached plain snapshots');

  // 6. release() detaches the proxy from the link.
  const n = mgrT.size;
  mgrT.release();
  agentT.publish(row(3));
  await new Promise((r) => setTimeout(r, 50));
  assert.strictEqual(mgrT.size, n);
  console.log('ok 6 - release detaches the proxy');

  for (const p of [contactA, contactB, descr, agentT]) p.release();
  console.log('\nAll proxy tests passed.');
}

main().catch((e) => { console.error('FAIL:', e); process.exit(1); });
