'use strict';
/* ASN.1 value-notation tests: `name Type ::= value` data loading.
 * Run: node test/values.js */
const assert = require('node:assert');
const asnstream = require('../src/index.js');
const { MibRegistry } = asnstream;

const SCHEMA = `ChatModule DEFINITIONS ::= BEGIN
  Message ::= SEQUENCE {
    sender UTF8String,
    body UTF8String,
    tags SEQUENCE OF UTF8String,
    priority [0] IMPLICIT INTEGER OPTIONAL,
    sentAt [1] EXPLICIT UTCTime OPTIONAL}

  Presence ::= ENUMERATED { away(0), online(1), busy(2)}

  Envelope ::= CHOICE {
    chat [0] EXPLICIT Message,
    ping [1] IMPLICIT UTF8String}

  Roster ::= SEQUENCE OF Message

  MyArc ::= OBJECT IDENTIFIER

  greeting Message ::= {
    sender "jeremy",
    body "hello back",
    tags { "mesh", "bbs" },
    priority 1 }

  -- a comment between assignments is fine
  minimal Message ::= { sender "sysop", body "motd", tags { } }

  status Presence ::= busy
  headcount INTEGER ::= 42
  negative INTEGER ::= -7
  flag BOOLEAN ::= TRUE
  nothing NULL ::= NULL
  blob OCTET STRING ::= 'DEADBEEF'H
  bits BIT STRING ::= '1010'B
  arc MyArc ::= { 1 3 6 1 }
  namedArc MyArc ::= { iso(1) org(3) dod(6) 1 }
  poke Envelope ::= { ping "are you there" }
  team Roster ::= {
    { sender "a", body "x", tags { } },
    { sender "b", body "y", tags { "t" }, priority 3 } }
END`;

function registry() {
  const reg = new MibRegistry();
  reg.loadModule(SCHEMA, 'ChatModule'); // schema + values in one pass
  reg.autoAssignOids('1.3.6.1.4.1.99999');
  return reg;
}

// -- values parse to the expected JS ---------------------------------------
{
  const reg = registry();
  assert.deepStrictEqual(reg.valueOf('greeting'), {
    sender: 'jeremy', body: 'hello back', tags: ['mesh', 'bbs'], priority: 1,
  });
  assert.deepStrictEqual(reg.valueOf('minimal'), { sender: 'sysop', body: 'motd', tags: [] });
  assert.strictEqual(reg.valueOf('status'), 2); // busy(2) -> number
  assert.strictEqual(reg.valueType('status'), 'Presence');
  assert.strictEqual(reg.valueOf('headcount'), 42);
  assert.strictEqual(reg.valueOf('negative'), -7);
  assert.strictEqual(reg.valueOf('flag'), true);
  assert.strictEqual(reg.valueOf('nothing'), null);
  assert.ok(reg.valueOf('blob').equals(Buffer.from('deadbeef', 'hex')));
  assert.ok(reg.valueOf('bits').equals(Buffer.from([0b10100000])));
  assert.strictEqual(reg.valueOf('arc'), '1.3.6.1');
  assert.strictEqual(reg.valueOf('namedArc'), '1.3.6.1');
  assert.deepStrictEqual(reg.valueOf('poke'), { choice: 'ping', value: 'are you there' });
  assert.deepStrictEqual(reg.valueOf('team'), [
    { sender: 'a', body: 'x', tags: [] },
    { sender: 'b', body: 'y', tags: ['t'], priority: 3 },
  ]);
  assert.ok(reg.valueNames().includes('greeting'));
}

// -- loaded data rides the wire: encode a value, decode it back -------------
{
  const reg = registry();
  const roundTripped = asnstream.decodeMessage(reg, 'Message', asnstream.encodeMessage(reg, 'Message', reg.valueOf('greeting')));
  // (absent OPTIONALs decode as explicit undefined keys — codec behavior)
  assert.strictEqual(roundTripped.sender, 'jeremy');
  assert.strictEqual(roundTripped.body, 'hello back');
  assert.deepStrictEqual(roundTripped.tags, ['mesh', 'bbs']);
  assert.strictEqual(roundTripped.priority, 1);
  assert.strictEqual(roundTripped.sentAt, undefined);

  // value straight into a live proxy publish path
  const roster = asnstream.marshal(reg, 'Roster', { send() {}, onMessage() { return () => {}; } });
  roster.publish(reg.valueOf('team'));
  assert.strictEqual(roster.get(1).body, 'y');
  assert.strictEqual(roster.get(1).priority, 3);
}

// -- valueOf returns a copy; the table can't be corrupted -------------------
{
  const reg = registry();
  const g = reg.valueOf('greeting');
  g.tags.push('evil');
  g.sender = 'mallory';
  assert.deepStrictEqual(reg.valueOf('greeting').tags, ['mesh', 'bbs']);
}

// -- defineValue directly, without text --------------------------------------
{
  const reg = new MibRegistry();
  reg.loadText('M DEFINITIONS ::= BEGIN Point ::= SEQUENCE { x INTEGER, y INTEGER } END', 'M');
  reg.defineValue('origin', 'Point', { x: 0, y: 0 });
  assert.deepStrictEqual(reg.valueOf('origin'), { x: 0, y: 0 });
  assert.strictEqual(reg.valueType('origin'), 'Point');
  assert.throws(() => reg.defineValue('bad', 'Nope', {}), /Unknown type|unknown type/i);
  assert.throws(() => reg.valueOf('missing'), /Unknown value/);
}

// -- loadText rejects value assignments with a pointer to loadValues ---------
{
  const reg = new MibRegistry();
  assert.throws(
    () => reg.loadText('M DEFINITIONS ::= BEGIN x INTEGER ::= 1 END', 'M'),
    /loadValues\(\) or loadModule\(\)/
  );
  // ...but SMI macro definitions are schema, not values, and still load fine
  reg.loadText(
    'M DEFINITIONS ::= BEGIN\n' +
    'mib OBJECT IDENTIFIER ::= { 1 3 }\n' +
    'x OBJECT-TYPE ::= { mib 1 }\n' +
    'END', 'M');
}

// -- clear errors for bad data ------------------------------------------------
{
  const reg = new MibRegistry();
  reg.loadText('M DEFINITIONS ::= BEGIN S ::= SEQUENCE { a INTEGER } END', 'M');
  assert.throws(() => reg.loadValues('M DEFINITIONS ::= BEGIN v S ::= { b 1 } END'), /unknown field 'b'/);
  assert.throws(() => reg.loadValues('M DEFINITIONS ::= BEGIN v S ::= { a "x" } END'), /expected a number/);
  assert.throws(() => reg.loadValues('M DEFINITIONS ::= BEGIN v Nope ::= 1 END'), /unknown type 'Nope'/);
}

console.log('values: all tests passed');
