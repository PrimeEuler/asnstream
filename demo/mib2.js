'use strict';
/**
 * demo/mib2.js — a tiny SNMP-style agent streaming MIB-II ifTable rows.
 *
 *   node demo/mib2.js            run server + client in one process
 *   node demo/mib2.js --server   agent only (TCP 10161)
 *   node demo/mib2.js --client   client only
 *
 * Every 800ms the agent emits ifEntry rows with marching counters, framed as
 * OID-tagged BER — the same objects snmpwalk would show, minus SNMP itself.
 */
const path = require('node:path');
const asnstream = require('../src/index.js');

const MIBDIR = path.join(__dirname, '..', '..', 'asn2json', 'SMI', 'MIB');
const PORT = 10161;

const registry = asnstream.loadMibs(
  path.join(MIBDIR, 'RFC1155-SMI.mib'),
  path.join(MIBDIR, 'RFC-1212.mib'),
  path.join(MIBDIR, 'RFC1213-MIB-II.mib')
);

console.log('ifEntry  ->', registry.oidOf('ifEntry'));
console.log('ifDescr  ->', registry.oidOf('ifDescr'));

const ifaces = [
  { ifIndex: 1, ifDescr: 'lo',   ifType: 24, ifMtu: 65536, ifSpeed: 10000000,  phys: [0, 0, 0, 0, 0, 0] },
  { ifIndex: 2, ifDescr: 'eth0', ifType: 6,  ifMtu: 1500,  ifSpeed: 1000000000, phys: [0x02, 0x42, 0xac, 0x11, 0x00, 0x02] },
];

let tick = 0;
function row(iface) {
  const n = tick * 137 + iface.ifIndex * 7919;
  return {
    ifIndex: iface.ifIndex,
    ifDescr: iface.ifDescr,
    ifType: iface.ifType,
    ifMtu: iface.ifMtu,
    ifSpeed: iface.ifSpeed,
    ifPhysAddress: Buffer.from(iface.phys),
    ifAdminStatus: 1,
    ifOperStatus: 1,
    ifLastChange: tick * 80,
    ifInOctets: (1000000 + n * 1500) % 4294967296,
    ifInUcastPkts: 5000 + n,
    ifInNUcastPkts: 0,
    ifInDiscards: 0,
    ifInErrors: 0,
    ifInUnknownProtos: 0,
    ifOutOctets: (2000000 + n * 900) % 4294967296,
    ifOutUcastPkts: 4000 + n,
    ifOutNUcastPkts: 0,
    ifOutDiscards: 0,
    ifOutErrors: 0,
    ifOutQLen: 0,
    ifSpecific: '0.0',
  };
}

function runServer() {
  const server = asnstream.tcp.serve(registry, PORT, ({ encoder }) => {
    console.log('[agent] client connected');
    const timer = setInterval(() => {
      tick++;
      for (const iface of ifaces) encoder.write({ type: 'IfEntry', value: row(iface) });
      if (tick % 5 === 0) {
        encoder.write({ oid: registry.oidOf('sysDescr'), value: `asnstream demo agent, tick ${tick}` });
      }
    }, 800);
    encoder.on('close', () => clearInterval(timer));
  });
  server.on('listening', () => console.log(`[agent] listening on 127.0.0.1:${PORT}`));
  return server;
}

async function runClient() {
  const { decoder } = await asnstream.tcp.connect(registry, PORT);
  console.log('[client] connected, waiting for rows…\n');
  console.log('ifIndex  ifDescr  ifInOctets   ifOutOctets  ifOperStatus');
  decoder.on('data', (msg) => {
    if (msg.type === 'IfEntry') {
      const v = msg.value;
      console.log(
        String(v.ifIndex).padEnd(9),
        String(v.ifDescr).padEnd(8),
        String(v.ifInOctets).padEnd(13),
        String(v.ifOutOctets).padEnd(12),
        v.ifOperStatus === 1 ? 'up' : 'down',
        `   <${msg.oid}>`
      );
    } else if (msg.oid === registry.oidOf('sysDescr')) {
      console.log(`\n[sysDescr] ${msg.value}\n`);
    } else {
      console.log('[client] undecoded frame', msg.oid);
    }
  });
}

const mode = process.argv[2];
if (mode === '--server') runServer();
else if (mode === '--client') runClient().catch((e) => { console.error(e.message); process.exit(1); });
else {
  runServer();
  setTimeout(() => runClient().catch((e) => { console.error(e.message); process.exit(1); }), 300);
  setTimeout(() => { console.log('\ndemo done'); process.exit(0); }, 6000);
}
