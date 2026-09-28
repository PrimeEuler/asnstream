'use strict';
/* Generic-ASN.1 tests: anything beyond SMI/MIB — arbitrary modules in,
 * OID-tagged frames out, live proxies back.
 * Run: node test/schema.js */
const assert = require('node:assert');
const { PassThrough } = require('node:stream');

const asnstream = require('../src/index.js');
const { MibRegistry } = asnstream;
const { encodeMessage, decodeMessage } = asnstream;
const { MessageEncoder, MessageDecoder } = asnstream;
const { marshal, unmarshal, linkFromStreams } = asnstream;

// NOTE: asn2json wants OPTIONAL hugging its terminator: `OPTIONAL,` or
// `OPTIONAL}` — a space before `,`/`}` is a parse error.
const CHAT = `
ChatModule DEFINITIONS ::= BEGIN
  Message ::= SEQUENCE {
    sender UTF8String,
    body UTF8String,
    tags SEQUENCE OF UTF8String,
    priority [0] IMPLICIT INTEGER OPTIONAL,
    sentAt [1] EXPLICIT UTCTime OPTIONAL}
  Presence ::= ENUMERATED { away(0), online(1), busy(2) }
  Envelope ::= CHOICE { chat [0] EXPLICIT Message, ping [1] IMPLICIT UTF8String }
  Roster ::= SEQUENCE OF Message
  Note ::= SEQUENCE { title UTF8String, body UTF8String OPTIONAL}
END`;

const PEN = '1.3.6.1.4.1.99999';

function registry() {
  const reg = new MibRegistry();
  reg.loadText(CHAT, 'ChatModule');
  reg.autoAssignOids(PEN);
  return reg;
}

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

const msgFull = () => ({
  sender: 'jeremy',
  body: 'hello',
  tags: ['mesh', 'bss'],
  priority: 1,
  sentAt: new Date('2026-09-28T12:00:00Z'),
});
const msgSparse = () => ({ sender: 'x', body: 'y', tags: [] });

async function main() {
  const reg = registry();

  // 1. OID assignment: every named type rides the wire; reverse lookup works.
  for (const t of ['Message', 'Presence', 'Envelope', 'Roster', 'Note']) {
    const oid = reg.oidOf(t);
    assert.ok(oid.startsWith(PEN + '.'), `${t} -> ${oid}`);
    assert.strictEqual(reg.typeOfOid(oid), t);
    assert.strictEqual(reg.oidOfType(t), oid);
  }
  console.log('ok 1 - autoAssignOids: every type gets a wire OID, both directions resolve');

  // 2. setTypeOid pins an explicit OID.
  const reg2 = new MibRegistry();
  reg2.loadText('M DEFINITIONS ::= BEGIN Ping ::= UTF8String END', 'M');
  reg2.setTypeOid('Ping', '1.2.3.4');
  assert.strictEqual(reg2.oidOf('Ping'), '1.2.3.4');
  assert.strictEqual(reg2.typeOfOid('1.2.3.4'), 'Ping');
  console.log('ok 2 - setTypeOid: explicit OID pinning');

  // 3. Full Message round-trip: UTF8String, SEQUENCE OF, IMPLICIT + EXPLICIT
  //    tagged optionals, UTCTime <-> Date.
  const rt = decodeMessage(reg, 'Message', encodeMessage(reg, 'Message', msgFull()));
  assert.strictEqual(rt.sender, 'jeremy');
  assert.strictEqual(rt.body, 'hello');
  assert.deepStrictEqual(rt.tags, ['mesh', 'bss']);
  assert.strictEqual(rt.priority, 1);
  assert.ok(rt.sentAt instanceof Date);
  assert.strictEqual(rt.sentAt.getTime(), new Date('2026-09-28T12:00:00Z').getTime());
  console.log('ok 3 - Message round-trip with tagged optionals and UTCTime');

  // 4. Sparse Message: absent optionals decode as undefined.
  const rs = decodeMessage(reg, 'Message', encodeMessage(reg, 'Message', msgSparse()));
  assert.strictEqual(rs.sender, 'x');
  assert.deepStrictEqual(rs.tags, []);
  assert.strictEqual(rs.priority, undefined);
  assert.strictEqual(rs.sentAt, undefined);
  console.log('ok 4 - absent tagged optionals decode as undefined');

  // 5. Trailing untagged OPTIONAL: present and absent.
  const n1 = decodeMessage(reg, 'Note', encodeMessage(reg, 'Note', { title: 't', body: 'b' }));
  assert.deepStrictEqual([n1.title, n1.body], ['t', 'b']);
  const n2 = decodeMessage(reg, 'Note', encodeMessage(reg, 'Note', { title: 't' }));
  assert.strictEqual(n2.title, 't');
  assert.strictEqual(n2.body, undefined);
  console.log('ok 5 - trailing untagged OPTIONAL present/absent');

  // 6. Named ENUMERATED: by symbol and by number.
  assert.strictEqual(decodeMessage(reg, 'Presence', encodeMessage(reg, 'Presence', 'busy')), 2);
  assert.strictEqual(decodeMessage(reg, 'Presence', encodeMessage(reg, 'Presence', 0)), 0);
  console.log('ok 6 - named ENUMERATED encodes by symbol or number');

  // 7. CHOICE with tagged alternatives, both ways.
  const c1 = decodeMessage(reg, 'Envelope',
    encodeMessage(reg, 'Envelope', { choice: 'chat', value: msgSparse() }));
  assert.strictEqual(c1.choice, 'chat');
  assert.strictEqual(c1.value.sender, 'x');
  const c2 = decodeMessage(reg, 'Envelope',
    encodeMessage(reg, 'Envelope', { choice: 'ping', value: 'yo' }));
  assert.deepStrictEqual(c2, { choice: 'ping', value: 'yo' });
  console.log('ok 7 - CHOICE with tagged alternatives round-trips');

  // 8. SEQUENCE OF round-trip.
  const rl = decodeMessage(reg, 'Roster', encodeMessage(reg, 'Roster', [msgSparse(), msgFull()]));
  assert.strictEqual(rl.length, 2);
  assert.strictEqual(rl[0].sender, 'x');
  assert.strictEqual(rl[1].priority, 1);
  console.log('ok 8 - SEQUENCE OF round-trip');

  // 9. Untagged OPTIONAL ahead of an untagged field is rejected at resolve
  //    time — ambiguous in BER, never a silent mis-decode.
  const bad = new MibRegistry();
  bad.loadText('M DEFINITIONS ::= BEGIN Bad ::= SEQUENCE { a INTEGER OPTIONAL, b BOOLEAN } END', 'M');
  assert.throws(() => bad.resolveType('Bad'), /untagged OPTIONAL.*ambiguous/);
  console.log('ok 9 - untagged mid-sequence OPTIONAL fails fast, not silently');

  // 10. The wire: { type, value } frames carry schema types end to end.
  {
    const a2b = new PassThrough();
    const enc = new MessageEncoder(reg);
    const dec = new MessageDecoder(reg);
    enc.pipe(a2b).pipe(dec);
    const got = new Promise((resolve) => dec.once('data', resolve));
    enc.write({ type: 'Message', value: msgFull() });
    const m = await got;
    assert.strictEqual(m.type, 'Message');
    assert.strictEqual(m.oid, reg.oidOf('Message'));
    assert.strictEqual(m.value.sender, 'jeremy');
    assert.strictEqual(m.value.priority, 1);
    console.log('ok 10 - MessageEncoder/Decoder carry schema types by OID');
  }

  // 11. Live StructProxy: publish from A, field-set from B, merge on A.
  {
    const { linkA, linkB } = duplexPair(reg);
    const structA = marshal(reg, 'Message', linkA);
    const structB = marshal(reg, 'Message', linkB);
    const gotB = once(structB, 'update');
    structA.publish(msgSparse());
    await gotB;
    assert.strictEqual(structB.sender, 'x');
    assert.strictEqual(structB.priority, undefined);
    const gotA = once(structA, 'update');
    structB.body = 'hello back';
    const [updA] = await gotA;
    assert.strictEqual(updA.body, 'hello back');
    assert.strictEqual(updA.sender, 'x'); // read-modify-write kept the rest
    assert.strictEqual(structA.body, 'hello back');
    console.log('ok 11 - StructProxy: publish, remote field-set, merged update');
  }

  // 12. marshal without a wire OID tells you how to fix it.
  {
    const bare = new MibRegistry();
    bare.loadText('M DEFINITIONS ::= BEGIN Lonely ::= SEQUENCE { a INTEGER } END', 'M');
    const { linkA } = duplexPair(bare);
    assert.throws(() => marshal(bare, 'Lonely', linkA), /has no OID on the wire.*setTypeOid/);
    console.log('ok 12 - missing OID fails with a helpful message');
  }

  // 13. Live ListProxy over Roster: element proxies, set, push, unmarshal.
  {
    const { linkA, linkB } = duplexPair(reg);
    const listA = marshal(reg, 'Roster', linkA);
    const listB = marshal(reg, 'Roster', linkB);
    const gotB = once(listB, 'update');
    listA.publish([msgSparse()]);
    await gotB;
    assert.strictEqual(listB.length, 1);
    assert.strictEqual(listB.get(0).sender, 'x');
    const gotA = once(listA, 'update');
    listB.get(0).priority = 5; // element field-set -> whole-array publish
    const [updA] = await gotA;
    assert.strictEqual(updA[0].priority, 5);
    assert.strictEqual(updA[0].sender, 'x');
    const gotA2 = once(listA, 'update');
    listB.push(msgFull());
    const [updA2] = await gotA2;
    assert.strictEqual(updA2.length, 2);
    assert.strictEqual(updA2[1].sender, 'jeremy');
    const snap = unmarshal(listA);
    assert.strictEqual(snap.length, 2);
    assert.strictEqual(snap[0].priority, 5);
    console.log('ok 13 - ListProxy: element proxies, set, push, unmarshal snapshot');
  }

  // 14. Scalar schema proxy: Presence as a live value; access override.
  {
    const { linkA, linkB } = duplexPair(reg);
    const presA = marshal(reg, 'Presence', linkA);
    const presB = marshal(reg, 'Presence', linkB);
    const gotB = once(presB, 'update');
    presA.value = 'busy';
    const [v] = await gotB;
    assert.strictEqual(v, 2);
    assert.strictEqual(presB.value, 2);
    const ro = marshal(reg, 'Presence', linkA, { access: 'read-only' });
    assert.throws(() => { ro.value = 'away'; }, /not writable \(ACCESS read-only\)/);
    console.log('ok 14 - scalar schema proxy publishes; { access } enforced');
  }

  // 15. release() detaches but keeps last-known state.
  {
    const { linkA, linkB } = duplexPair(reg);
    const structA = marshal(reg, 'Message', linkA);
    const structB = marshal(reg, 'Message', linkB);
    const gotB = once(structB, 'update');
    structA.publish(msgSparse());
    await gotB;
    structB.release();
    structA.publish(msgFull()); // B must not see this
    await new Promise((r) => setTimeout(r, 50));
    assert.strictEqual(structB.sender, 'x');
    assert.deepStrictEqual(unmarshal(structB).sender, 'x');
    console.log('ok 15 - release() detaches, keeps last-known struct');
  }

  console.log('\nAll schema tests passed.');
}

main().catch((err) => { console.error(err); process.exit(1); });
