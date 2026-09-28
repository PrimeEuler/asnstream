'use strict';
/**
 * tcp — TCP transport wiring MessageEncoder/MessageDecoder to net sockets.
 */
const net = require('net');
const { MessageEncoder, MessageDecoder } = require('./streams');

function wire(socket, registry) {
  const encoder = new MessageEncoder(registry);
  const decoder = new MessageDecoder(registry);
  socket.pipe(decoder);
  encoder.pipe(socket);
  return { socket, encoder, decoder };
}

/** Start a server; onConnection receives { socket, encoder, decoder }. */
function serve(registry, port, onConnection, host = '127.0.0.1') {
  const server = net.createServer(socket => onConnection(wire(socket, registry)));
  server.listen(port, host);
  return server;
}

/** Connect as a client; resolves with { socket, encoder, decoder }. */
function connect(registry, port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host, () => resolve(wire(socket, registry)));
    socket.on('error', reject);
  });
}

module.exports = { serve, connect, wire };
