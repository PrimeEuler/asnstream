# asnstream

A protobuf-style streaming system for ASN.1. Import MIBs — or any ASN.1
module — with [asn2json](https://github.com/PrimeEuler/asn2json), render BER
with [PeculiarVentures/ASN1.js](https://github.com/PeculiarVentures/ASN1.js),
and stream schema-driven binary messages the way protobuf streams do —
except the schema language is ASN.1 and every message is addressed by OID,
like SNMP itself.

## The idea

| protobuf              | asnstream                                        |
|-----------------------|--------------------------------------------------|
| `.proto` file         | ASN.1 module (MIB file, X.509-style schema, …)    |
| `protoc` codegen      | `asn2json` → JSON IR → registry                  |
| generated message     | `asn1js` schema compiled from the module         |
| length-delimited frame| `uint32BE len ‖ BER(SEQUENCE { type OID, payload OCTET STRING })` |
| gRPC stream           | TCP or WebSocket duplex of frames                |

Each frame is tagged with the type's OID, so one stream multiplexes
many message types — a table row, a scalar, a trap, a chat message — and
the receiver decodes each frame with the type registered for that OID.
SMI types carry their OID in `::=`; other ASN.1 types get one via
`setTypeOid`/`autoAssignOids`. Unknown OIDs pass through
as raw bytes instead of killing the stream (like an agent forwarding a VarBind
it has no MIB for).

## Wire format

```
+----------------+--------------------------------------------------+
| uint32 BE = N  | BER: SEQUENCE {                                  |
|                |   type    OBJECT IDENTIFIER  -- e.g. ifEntry    |
|                |   payload OCTET STRING     -- BER of the value |
|                | }  (N bytes)                                     |
+----------------+--------------------------------------------------+
```

The 4-byte prefix keeps the byte stream self-delimiting; BER alone cannot
resync after a torn frame.

## Usage

```js
const asnstream = require('asnstream');

// 1. Import MIBs (asn2json does the parsing)
const registry = asnstream.loadMibs('RFC1155-SMI.mib', 'RFC1213-MIB-II.mib');

registry.oidOf('ifDescr');        // '1.3.6.1.2.1.2.2.1.2'
registry.typeOfOid('1.3.6.1.2.1.2.2.1'); // 'IfEntry'

// 2. Encode / decode single messages (BER via ASN1.js)
const ber = asnstream.encodeMessage(registry, 'IfEntry', {
  ifIndex: 2, ifDescr: 'eth0', ifType: 6, ifMtu: 1500,
  ifSpeed: 1000000000, ifPhysAddress: Buffer.from('0242ac110002', 'hex'),
  ifAdminStatus: 1, ifOperStatus: 1, ifLastChange: 42,
  ifInOctets: 123456, /* ... all 22 fields ... */
  ifSpecific: '0.0',
});
const row = asnstream.decodeMessage(registry, 'IfEntry', ber);
row.ifDescr; // 'eth0'  (DisplayString <-> string)

// 3. Stream them over TCP — OID-tagged, multiplexed
const server = asnstream.tcp.serve(registry, 10161, ({ encoder }) => {
  setInterval(() => encoder.write({ type: 'IfEntry', value: row }), 1000);
});

const { decoder } = await asnstream.tcp.connect(registry, 10161);
decoder.on('data', (msg) => {
  // { oid: '1.3.6.1.2.1.2.2.1', type: 'IfEntry', value: {...} }
});
```

WebSocket works the same way (`asnstream.ws.serve` / `asnstream.ws.connect`,
binary frames). `MessageEncoder` / `MessageDecoder` are plain Node Transform
streams, so they compose with anything (`socket.pipe(decoder)`, file streams,
etc.).

## SMI fidelity

- `Counter`/`Counter32`, `Gauge`, `TimeTicks`, `IpAddress`, `Opaque` keep
  their SMI APPLICATION tags (implicit), so the BER matches what an SNMP
  agent would emit for the same object.
- `DisplayString` decodes to a JS string; other OCTET STRINGs to `Buffer`.
- `SIZE` and INTEGER range constraints from the MIB are enforced on encode.
- OBJECT-TYPE metadata (`objectInfo`: access, status, description, OID) is
  available from the registry.

Frames carry the OBJECT-TYPE OID (the *schema* identity, e.g. `ifEntry`),
not an instance OID (`ifEntry.2`); instance discrimination lives in the
payload's INDEX fields. This is the one deliberate departure from SNMP
VarBinds, and it is what makes the stream protobuf-like instead of
request/response-like.

## Live proxies — getters subscribe, setters publish

`src/proxy.js` marshals MIB objects into live remote objects over the
stream, the jsix accessor pattern backed by frames instead of Fibre:

```js
const { marshal, unmarshal, linkFromStreams } = require('asnstream');
const link = linkFromStreams(tcpLink.encoder, tcpLink.decoder);

// scalar object: read subscribes, write publishes
const contact = marshal(registry, 'sysContact', link); // read-write
contact.value = 'sysop@mesh';        // -> OID-tagged frame on the wire
console.log(contact.value);          // last-known value

// table: rows materialize as frames arrive, keyed by INDEX
const ifTable = marshal(registry, 'ifEntry', link);
ifTable.on('row', (row) => console.log('new interface:', row.ifDescr));
ifTable.get(3).ifAdminStatus = 2;    // publishes a full-row update
ifTable.get(3).ifDescr = 'x';        // throws: ACCESS read-only

const snap = unmarshal(ifTable);     // plain detached snapshot
ifTable.release();                   // detach; state frozen, not forgotten
```

Rules:

- Constructing a proxy subscribes it (one shared dispatcher per link, so
  N proxies cost one `data` listener). `release()` detaches.
- ACCESS is enforced at the language level: writing a read-only object or
  column throws; reading a `not-accessible` object throws.
- Row column setters do read-modify-write on the cached row and publish the
  full row — you cannot set a column of a row you have never seen.
- `TableProxy.publish(row)` is the agent side: announce a row from a poll
  loop. Events: `row` on first sight, `update` on every row update.
- Proxies also emit jsix-accessor-compatible `get`/`set` events for the
  browser bridge.

## Beyond SMI — any ASN.1 module rides the same wire

The registry is not MIB-specific: `loadText` parses any ASN.1 module, and
the codec handles the common type system — `SEQUENCE`, `CHOICE`,
`SEQUENCE OF`/`SET OF` (named, inline, or anonymous), named `ENUMERATED`
(by symbol or number), `UTF8String`/`PrintableString`/`IA5String`/
`VisibleString`/`NumericString`/`BMPString`/`UniversalString`/
`TeletexString`/`GeneralString`, `UTCTime`/`GeneralizedTime` (as JS
`Date`), `BOOLEAN`, `NULL`, `BIT STRING`, `OBJECT IDENTIFIER`, and
`[n] IMPLICIT`/`EXPLICIT` field tags (the X.509 shape — tagged optionals
may sit anywhere; untagged optionals must trail, else resolution throws
instead of silently mis-decoding).

Types need a wire OID. SMI types have one from `::=`; anything else gets
one explicitly or automatically:

```js
reg.loadText(fs.readFileSync('chat.asn1', 'utf8'), 'ChatModule');
reg.autoAssignOids('1.3.6.1.4.1.99999');   // stable, sorted by type name
// or: reg.setTypeOid('Message', '1.3.6.1.4.1.99999.2');

// the stream layer needs no changes — { type, value } just works
encoder.write({ type: 'Message', value: { sender: 'jeremy', body: 'hi', tags: [] } });

// and neither does marshal(): SEQUENCE -> live struct, SEQUENCE OF -> live list
const msg = marshal(reg, 'Message', link);
msg.on('update', (m) => console.log(m.sender, m.body));
msg.body = 'hello back';              // publishes the whole struct

const roster = marshal(reg, 'Roster', link);   // SEQUENCE OF Message
roster.get(0).priority = 5;           // element field-set -> array publish
roster.push({ sender: 'x', body: 'y', tags: [] });
```

Schema types default to read-write (`marshal(reg, name, link, { access:
'read-only' })` to restrict); marshaling a type with no OID throws a
message telling you to assign one. MIB OBJECT-TYPEs keep their exact
previous behavior, including ACCESS and INDEX tables.

Parser quirks worth knowing (both from `asn2json`, not from this layer):

- `OPTIONAL` must hug its terminator: `OPTIONAL,` or `OPTIONAL}` — a
  space before the comma/brace is a parse error.
- A single-field `SEQUENCE`/`CHOICE` parses as one bare tuple, not an
  array of tuples; `Roster ::= SEQUENCE OF X` parses as
  `["SEQUENCE OF", "X"]` while `SET OF` parses as `{"SET OF": "X"}`.
  The registry normalizes all of these.

## ASN.1 values — populate structures with text

Modules can carry data, not just schema. `loadValues` (or `loadModule`
for both at once) parses ASN.1 value notation and stores named values:

```asn1
ChatData DEFINITIONS ::= BEGIN
  greeting Message ::= {
    sender "jeremy",
    body "hello back",
    tags { "mesh", "bbs" },
    priority 1
  }
  status Presence ::= online
  inbox Roster ::= { greeting }
END
```

```js
reg.loadText(schemaText, 'Chat');          // schema, as before
reg.loadValues(dataText);                  // data, validated against it
// or: reg.loadModule(moduleText, 'Chat'); // schema + values in one pass

reg.valueOf('greeting');   // { sender: 'jeremy', body: 'hello back', ... }
reg.valueNames();          // ['greeting', 'status', 'inbox', ...]
reg.valueType('greeting'); // 'Message'

// loaded values encode, decode, and publish like anything else
encoder.write({ type: 'Message', value: reg.valueOf('greeting') });
const msg = marshal(reg, 'Message', link);
Object.assign(msg, reg.valueOf('greeting'));  // setters publish
```

Scalars, enums (by symbol), `CHOICE`, `SEQUENCE OF`/`SET OF`, hex/octet
and binary `BIT STRING`s, `OBJECT IDENTIFIER`s, and time strings (as
`Date`) are all supported. Values are type-checked at load; `valueOf`
returns a defensive copy. (`loadText` refuses data assignments with a
pointer to `loadValues`, because the schema parser would silently
misread them.)

## RPC — callable code lives in the OID tree

`defineProcedure` namespaces a procedure under an OID node; the call
envelope rides at `P.0` and the result envelope at `P.1`, so remote calls
are just frame publishes and the registry doubles as a walkable
directory of callable code:

```js
const add = asnstream.defineProcedure(reg, 'add', {
  args: 'AddArgs', result: 'AddResult', oid: '1.3.6.1.4.1.99999.7.1',
});
asnstream.serveProcedure(serverLink, add, ({ a, b }) => ({ sum: a + b }));
const { sum } = await asnstream.callProcedure(clientLink, add, { a: 3, b: 4 });
```

Handlers may be async; concurrent calls correlate by `callId`;
server-side exceptions reject the caller's promise with the server's
error string; calls time out (default 10s, `{ timeout }` overrides).
`serveProcedure` returns an `unserve()` function, and
`reg.procedures()` / `asnstream.listProcedures(reg)` lists what's defined.

## Layout

```
src/registry.js  ASN.1 loading via asn2json, type resolution, OID tree (+ assignment)
src/codec.js     JS values <-> BER via compiled asn1js schemas
src/frame.js     OID-tagged length-delimited framing + incremental splitter
src/streams.js   MessageEncoder / MessageDecoder Transform streams
src/proxy.js     live remote objects: marshal / unmarshal, ACCESS, tables, structs, lists
src/values.js    ASN.1 value-notation parsing (loadValues / loadModule)
src/rpc.js       OID-namespaced remote procedures
src/tcp.js       TCP transport
src/ws.js        WebSocket transport (needs the `ws` package)
demo/mib2.js     fake agent streaming MIB-II ifTable rows (npm run demo)
test/test.js     round-trip suite (npm test)
test/proxy.js    live-proxy suite (npm test)
test/schema.js   generic-ASN.1 suite (npm test)
test/values.js   value-notation suite (npm test)
test/rpc.js      RPC suite (npm test)
```

## Status

Sandbox prototype, 2026-09-28. BER only (no SNMP PDU layer — by design;
this is a streaming transport, not an SNMP stack). Notable asn1js v3 quirk
handled inside: typed constructors hard-override `idBlock`, so SMI
application tags are applied post-construction.
