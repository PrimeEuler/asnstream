'use strict';
/**
 * frame — OID-tagged message frames, SMI-style.
 *
 * Each frame on the wire is:
 *   uint32BE length N  ||  BER( SEQUENCE { type OBJECT IDENTIFIER, payload OCTET STRING } )
 *
 * The OID names the MIB object whose SYNTAX describes the payload, so one
 * stream multiplexes many object types — like an SNMP VarBind stripped of
 * the request/response machinery. The 4-byte prefix keeps the byte stream
 * self-delimiting (BER alone can't resync after a torn frame).
 */
const asn1js = require('asn1js');

const frameSchema = () => new asn1js.Sequence({
  value: [
    new asn1js.ObjectIdentifier({ name: 'type' }),
    new asn1js.OctetString({ name: 'payload' }),
  ],
});

function encodeFrame(oid, payload) {
  const bytes = Buffer.from(payload);
  const frame = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: oid }),
      new asn1js.OctetString({ valueHex: bytes }),
    ],
  });
  const ber = Buffer.from(frame.toBER(false));
  const out = Buffer.allocUnsafe(4 + ber.length);
  out.writeUInt32BE(ber.length, 0);
  ber.copy(out, 4);
  return out;
}

function decodeFrameBody(ber) {
  const ab = ber.buffer.slice(ber.byteOffset, ber.byteOffset + ber.byteLength);
  const parsed = asn1js.fromBER(ab);
  if (parsed.offset === -1) throw new Error('Frame BER parse failed');
  const compared = asn1js.compareSchema(parsed.result, parsed.result, frameSchema());
  if (!compared.verified) throw new Error('Frame schema mismatch');
  const children = parsed.result.valueBlock.value;
  return {
    oid: children[0].valueBlock.toString(),
    payload: Buffer.from(children[1].valueBlock.valueHex),
  };
}

/**
 * Incremental frame splitter: feed arbitrary TCP/WS chunks, get whole frames.
 */
class FrameDecoder {
  constructor(maxFrame = 64 * 1024 * 1024) {
    this.buffer = Buffer.alloc(0);
    this.maxFrame = maxFrame;
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    const frames = [];
    for (;;) {
      if (this.buffer.length < 4) break;
      const len = this.buffer.readUInt32BE(0);
      if (len > this.maxFrame) throw new Error(`Frame too large: ${len}`);
      if (this.buffer.length < 4 + len) break;
      const body = this.buffer.subarray(4, 4 + len);
      this.buffer = this.buffer.subarray(4 + len);
      frames.push(decodeFrameBody(body));
    }
    return frames;
  }
}

module.exports = { encodeFrame, decodeFrameBody, FrameDecoder };
