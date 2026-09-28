'use strict';
/**
 * ws — WebSocket transport (binary frames) wiring the same streams.
 * Requires the `ws` package (optional dependency).
 */
const { MessageEncoder, MessageDecoder } = require('./streams');

function wireBinary(ws, registry) {
  const encoder = new MessageEncoder(registry);
  const decoder = new MessageDecoder(registry);
  ws.on('message', data => decoder.write(Buffer.from(data)));
  encoder.on('data', buf => { if (ws.readyState === 1) ws.send(buf); });
  const close = () => { encoder.end(); decoder.end(); };
  ws.on('close', close);
  ws.on('error', close);
  return { ws, encoder, decoder };
}

function serve(registry, port, onConnection) {
  const { WebSocketServer } = require('ws');
  const wss = new WebSocketServer({ port });
  wss.on('connection', ws => onConnection(wireBinary(ws, registry)));
  return wss;
}

function connect(registry, url) {
  const { WebSocket } = require('ws');
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.on('open', () => resolve(wireBinary(ws, registry)));
    ws.on('error', reject);
  });
}

module.exports = { serve, connect, wireBinary };
