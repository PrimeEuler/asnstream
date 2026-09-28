'use strict';
/**
 * asnstream — protobuf-style streaming for SNMP MIBs.
 *
 *   MIB text --(asn2json)--> JSON IR --(registry)--> resolved types + OID tree
 *            --(codec)--> asn1js BER --(frame)--> OID-tagged length-delimited
 *            frames --(streams/tcp/ws)--> the wire
 */
const { MibRegistry } = require('./registry');
const codec = require('./codec');
const frame = require('./frame');
const streams = require('./streams');
const tcp = require('./tcp');
const proxy = require('./proxy');

let ws = null;
try { ws = require('./ws'); } catch { /* 'ws' is optional */ }

/** Load MIB files and return a ready registry. */
function loadMibs(...files) {
  const registry = new MibRegistry();
  for (const f of files) registry.loadFile(f);
  return registry;
}

module.exports = {
  MibRegistry,
  loadMibs,
  encodeMessage: codec.encodeMessage,
  decodeMessage: codec.decodeMessage,
  encodeFrame: frame.encodeFrame,
  FrameDecoder: frame.FrameDecoder,
  MessageEncoder: streams.MessageEncoder,
  MessageDecoder: streams.MessageDecoder,
  marshal: proxy.marshal,
  unmarshal: proxy.unmarshal,
  linkFromStreams: proxy.linkFromStreams,
  ValueProxy: proxy.ValueProxy,
  RowProxy: proxy.RowProxy,
  TableProxy: proxy.TableProxy,
  StructProxy: proxy.StructProxy,
  ElementProxy: proxy.ElementProxy,
  ListProxy: proxy.ListProxy,
  tcp,
  ws,
};
