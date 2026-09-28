'use strict';
/* RPC tests: procedures namespaced in the OID tree, called over a link.
 * Run: node test/rpc.js */
const assert = require('node:assert');
const { PassThrough } = require('node:stream');

const asnstream = require('../src/index.js');
const { MibRegistry, MessageEncoder, MessageDecoder, linkFromStreams } = asnstream;
const { defineProcedure, listProcedures, serveProcedure, callProcedure } = asnstream;

const SCHEMA = `RpcModule DEFINITIONS ::= BEGIN
  AddArgs ::= SEQUENCE { a INTEGER, b INTEGER }
  AddResult ::= SEQUENCE { sum INTEGER }
  GreetArgs ::= SEQUENCE { name UTF8String }
  GreetResult ::= UTF8String
END`;

function registry() {
  const reg = new MibRegistry();
  reg.loadText(SCHEMA, 'RpcModule');
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

async function main() {
  // -- definition: OID layout, envelope types, registry directory ------------
  {
    const reg = registry();
    const proc = defineProcedure(reg, 'add', {
      args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.1',
    });
    assert.strictEqual(proc.callOid, '1.3.6.1.4.1.99999.7.1.0');
    assert.strictEqual(proc.resultOid, '1.3.6.1.4.1.99999.7.1.1');
    assert.strictEqual(reg.oidOf('add$Call'), proc.callOid);
    assert.strictEqual(reg.oidOf('add$Result'), proc.resultOid);
    assert.deepStrictEqual(listProcedures(reg).map((p) => p.name), ['add']);

    // envelope round-trips through the codec
    const callMsg = asnstream.decodeMessage(
      reg, 'add$Call', asnstream.encodeMessage(reg, 'add$Call', { callId: 7, args: { a: 3, b: 4 } }));
    assert.deepStrictEqual(callMsg, { callId: 7, args: { a: 3, b: 4 } });

    const okMsg = asnstream.decodeMessage(
      reg, 'add$Result', asnstream.encodeMessage(reg, 'add$Result', { callId: 7, outcome: { choice: 'ok', value: { sum: 7 } } }));
    assert.deepStrictEqual(okMsg.outcome, { choice: 'ok', value: { sum: 7 } });

    const errMsg = asnstream.decodeMessage(
      reg, 'add$Result', asnstream.encodeMessage(reg, 'add$Result', { callId: 7, outcome: { choice: 'err', value: 'boom' } }));
    assert.deepStrictEqual(errMsg.outcome, { choice: 'err', value: 'boom' });

    assert.throws(() => defineProcedure(reg, 'add', { args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.9' }), /already defined/);
    assert.throws(() => defineProcedure(reg, 'nope', { args: 'Missing', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.9' }), /Unknown type/);
    assert.throws(() => defineProcedure(reg, 'noid', { args: 'AddArgs', result: 'AddResult' }), /needs a dotted oid/);
  }

  // -- live call over a link: serve on one end, call from the other ---------
  {
    const reg = registry();
    const add = defineProcedure(reg, 'add', { args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.1' });
    const greet = defineProcedure(reg, 'greet', { args: 'GreetArgs', result: 'GreetResult', oid: '1.3.6.1.4.1.99999.7.2' });
    const { linkA, linkB } = duplexPair(reg);

    const unserveAdd = serveProcedure(linkA, add, ({ a, b }) => ({ sum: a + b }));
    serveProcedure(linkA, greet, async ({ name }) => `hello, ${name}`);

    const r1 = await callProcedure(linkB, add, { a: 20, b: 22 });
    assert.deepStrictEqual(r1, { sum: 42 });
    const r2 = await callProcedure(linkB, greet, { name: 'jeremy' });
    assert.strictEqual(r2, 'hello, jeremy');

    // concurrent calls correlate by callId
    const [c1, c2, c3] = await Promise.all([
      callProcedure(linkB, add, { a: 1, b: 1 }),
      callProcedure(linkB, add, { a: 2, b: 3 }),
      callProcedure(linkB, greet, { name: 'mesh' }),
    ]);
    assert.deepStrictEqual([c1.sum, c2.sum, c3], [2, 5, 'hello, mesh']);

    // handler exceptions come back as rejections
    const fail = defineProcedure(reg, 'fail', { args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.3' });
    serveProcedure(linkA, fail, () => { throw new Error('kaboom'); });
    await assert.rejects(callProcedure(linkB, fail, { a: 1, b: 2 }), /kaboom/);

    // unserve stops the server side; the call then times out
    unserveAdd();
    await assert.rejects(callProcedure(linkB, add, { a: 1, b: 1 }, { timeout: 200 }), /timed out/);
  }

  console.log('rpc: all tests passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
