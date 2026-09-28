'use strict';
/**
 * RPC over the OID bus: procedures are namespaced in the OID tree, so a
 * remote call is just a frame publish and a result subscription.
 *
 *   const proc = defineProcedure(registry, 'add', {
 *     args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.1',
 *   });
 *   serveProcedure(serverLink, proc, ({ a, b }) => ({ sum: a + b }));
 *   const { sum } = await callProcedure(clientLink, proc, { a: 3, b: 4 });
 *
 * Layout: a procedure at OID P exposes two message types as children —
 * P.0 is the call envelope, P.1 the result envelope:
 *
 *   <name>$Call   ::= SEQUENCE { callId INTEGER, args <args> }
 *   <name>$Result ::= SEQUENCE { callId INTEGER,
 *                       outcome CHOICE { ok  [0] EXPLICIT <result>,
 *                                        err [1] IMPLICIT UTF8String } }
 *
 * The envelopes are synthesized straight into the registry (registerType)
 * and pinned to P.0/P.1, so `registry.procedures()` plus the OID tree is
 * a complete, walkable directory of callable code — no out-of-band IDL.
 * callId correlates concurrent calls; handler exceptions travel back as
 * rejected promises carrying the server's error string.
 */
const { hubAdd, hubRemove } = require('./proxy');

/**
 * Define a procedure in the OID namespace. `args`/`result` name the ASN.1
 * types of the argument and result values; `oid` is the procedure's own
 * node (call envelope at oid.0, result envelope at oid.1).
 */
function defineProcedure(registry, name, { args, result, oid }) {
  if (!name || typeof name !== 'string') throw new Error('defineProcedure needs a name');
  if (!args || !result) throw new Error(`defineProcedure('${name}') needs { args, result } type names`);
  if (!oid || !/^[0-9]+(\.[0-9]+)*$/.test(oid)) {
    throw new Error(`defineProcedure('${name}') needs a dotted oid for the procedure node`);
  }
  if (registry._procedures.has(name)) throw new Error(`procedure '${name}' is already defined`);
  registry.resolveType(args);   // throws on unknown types
  registry.resolveType(result);

  const callType = `${name}$Call`;
  const resultType = `${name}$Result`;
  const callOid = `${oid}.0`;
  const resultOid = `${oid}.1`;

  registry.registerType(callType, {
    SEQUENCE: [['callId', 'INTEGER'], ['args', args]],
  });
  registry.registerType(resultType, {
    SEQUENCE: [
      ['callId', 'INTEGER'],
      ['outcome', { CHOICE: [
        ['ok', { tag: { class: null, number: 0 }, definition: 'EXPLICIT', type: result }],
        ['err', { tag: { class: null, number: 1 }, definition: 'IMPLICIT', type: 'UTF8String' }],
      ] }],
    ],
  });
  registry.setTypeOid(callType, callOid);
  registry.setTypeOid(resultType, resultOid);

  const proc = { name, oid, args, result, callType, resultType, callOid, resultOid, registry };
  registry._procedures.set(name, proc);
  return proc;
}

/** Procedures defined on this registry. */
function listProcedures(registry) {
  return registry.procedures();
}

let nextCallId = 1;

/**
 * Serve a procedure on a link: incoming call frames are decoded, the
 * handler runs (sync or async), and the result — or the thrown error —
 * is published on the result OID. Returns an unserve function.
 */
function serveProcedure(link, proc, handler) {
  if (typeof handler !== 'function') throw new Error(`serveProcedure('${proc.name}') needs a handler function`);
  const onFrame = async (msg) => {
    if (!msg || msg.type === null || msg.type === undefined) return;
    const { callId, args } = msg.value;
    try {
      const value = await handler(args, { callId, proc, link });
      link.send({ oid: proc.resultOid, type: proc.resultType, value: { callId, outcome: { choice: 'ok', value } } });
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      link.send({ oid: proc.resultOid, type: proc.resultType, value: { callId, outcome: { choice: 'err', value: message } } });
    }
  };
  hubAdd(link, proc.callOid, onFrame);
  return () => hubRemove(link, proc.callOid, onFrame);
}

/**
 * Call a procedure on a link. Publishes the call envelope and resolves
 * with the result value, or rejects with the server's error / a timeout.
 */
function callProcedure(link, proc, args, { timeout = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const callId = nextCallId > 0x7fffffff ? (nextCallId = 1) : nextCallId++;
    const done = (fn) => (value) => { clearTimeout(timer); hubRemove(link, proc.resultOid, onFrame); fn(value); };
    const timer = setTimeout(
      () => { hubRemove(link, proc.resultOid, onFrame); reject(new Error(`RPC '${proc.name}' timed out after ${timeout}ms`)); },
      timeout
    );
    const onFrame = (msg) => {
      if (!msg || msg.type === null || msg.type === undefined) return;
      const res = msg.value;
      if (!res || res.callId !== callId) return; // not our call
      const out = res.outcome;
      if (out && out.choice === 'ok') done(resolve)(out.value);
      else done(reject)(new Error(`RPC '${proc.name}' failed: ${out ? out.value : 'malformed result'}`));
    };
    hubAdd(link, proc.resultOid, onFrame);
    try {
      link.send({ oid: proc.callOid, type: proc.callType, value: { callId, args } });
    } catch (err) {
      done(reject)(err);
    }
  });
}

module.exports = { defineProcedure, listProcedures, serveProcedure, callProcedure };
