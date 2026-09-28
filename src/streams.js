'use strict';
/**
 * streams — Node Transform streams for OID-tagged MIB message flow.
 *
 *   MessageEncoder:  writable object mode, readable bytes.
 *     in:  { type: 'IfEntry', value: {...} }   (OID resolved from registry)
 *     or:  { oid: '1.3.6.1.2.1.2.2.1', value: {...} }
 *     out: framed BER buffers
 *
 *   MessageDecoder:  writable bytes, readable object mode.
 *     in:  arbitrary chunks of framed BER
 *     out: { oid, type, value }  (or { oid, type: null, raw } for unknown OIDs)
 */
const { Transform } = require('stream');
const { encodeMessage, decodeMessage } = require('./codec');
const { encodeFrame, FrameDecoder } = require('./frame');

class MessageEncoder extends Transform {
  constructor(registry, options = {}) {
    super(Object.assign({ writableObjectMode: true }, options));
    this.registry = registry;
  }

  _transform(msg, _enc, cb) {
    try {
      const oid = msg.oid || this.registry.oidOfType(msg.type);
      const typeName = msg.type || this.registry.typeOfOid(oid);
      const payload = encodeMessage(this.registry, typeName, msg.value);
      this.push(encodeFrame(oid, payload));
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

class MessageDecoder extends Transform {
  constructor(registry, options = {}) {
    super(Object.assign({ readableObjectMode: true }, options));
    this.registry = registry;
    this.frames = new FrameDecoder(options.maxFrame);
  }

  _transform(chunk, _enc, cb) {
    try {
      for (const { oid, payload } of this.frames.push(chunk)) {
        let type = null;
        let value;
        try {
          type = this.registry.typeOfOid(oid);
          value = decodeMessage(this.registry, type, payload);
          this.push({ oid, type, value });
        } catch {
          // Unknown OID or undecodable payload: pass through raw, like an
          // SNMP agent forwarding a VarBind it has no MIB for.
          this.push({ oid, type, raw: payload });
        }
      }
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

module.exports = { MessageEncoder, MessageDecoder };
