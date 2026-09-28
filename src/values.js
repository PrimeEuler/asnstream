'use strict';
/**
 * ASN.1 value notation: `name Type ::= value` assignments.
 *
 * asn2json only parses schema (type) definitions, so data lives here:
 * a small tokenizer + type-directed recursive-descent parser that turns
 * value assignments into plain JavaScript values validated against the
 * registry's resolved types.
 *
 * Supported value syntax:
 *   greeting Message ::= { sender "jeremy", body "hi", tags { "a", "b" } }
 *   status   Presence ::= busy            -- enumerated symbol -> number
 *   count    INTEGER  ::= 42
 *   flag     BOOLEAN  ::= TRUE
 *   nothing  NULL     ::= NULL
 *   blob     OCTET STRING ::= 'DEADBEEF'H
 *   bits     BIT STRING ::= '1010'B
 *   when     UTCTime  ::= "260928180000Z"
 *   arc      OBJECT IDENTIFIER ::= { 1 3 6 1 }
 *   pick     Choice   ::= { text "hi" }  -- { alternative value }
 *   roster   Roster   ::= { { sender "a", ... }, { sender "b", ... } }
 *
 * A value assignment is recognized as `ident ident ::= value` at module
 * level (two identifiers before `::=`; type assignments have one, and the
 * `M DEFINITIONS ::= BEGIN` header is skipped explicitly).
 */

function tokenize(text) {
  const toks = [];
  let i = 0, line = 1;
  const fail = (msg) => { throw new Error(`values: ${msg} (line ${line})`); };
  const emit = (tok, start) => { tok.start = start; tok.end = i; toks.push(tok); };
  while (i < text.length) {
    const start = i;
    const c = text[i];
    if (c === '\n') { line++; i++; continue; }
    if (c === '\r' || c === ' ' || c === '\t' || c === '\f' || c === '\v') { i++; continue; }
    if (c === '-' && text[i + 1] === '-') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === ':' && text[i + 1] === ':' && text[i + 2] === '=') {
      i += 3; emit({ t: 'punct', v: '::=', line }, start); continue;
    }
    if (c === '"') { // "..." with "" escape
      let s = ''; i++;
      for (;;) {
        if (i >= text.length) fail('unterminated string');
        if (text[i] === '"' && text[i + 1] === '"') { s += '"'; i += 2; continue; }
        if (text[i] === '"') { i++; break; }
        if (text[i] === '\n') line++;
        s += text[i]; i++;
      }
      emit({ t: 'string', v: s, line }, start); continue;
    }
    if (c === "'") { // 'FF'H | '1010'B
      let s = ''; i++;
      while (i < text.length && text[i] !== "'") s += text[i++];
      if (text[i] !== "'") fail('unterminated quoted value');
      i++;
      const suf = text[i];
      if (suf === 'B' || suf === 'H') { i++; emit({ t: suf === 'B' ? 'bits' : 'hex', v: s, line }, start); }
      else emit({ t: 'string', v: s, line }, start);
      continue;
    }
    if (/[0-9]/.test(c) || (c === '-' && /[0-9]/.test(text[i + 1] || ''))) {
      let s = '';
      if (c === '-') { s += c; i++; }
      while (i < text.length && /[0-9]/.test(text[i])) s += text[i++];
      emit({ t: 'number', v: parseInt(s, 10), line }, start); continue;
    }
    if (/[A-Za-z]/.test(c)) {
      let s = '';
      while (i < text.length && /[A-Za-z0-9_-]/.test(text[i])) s += text[i++];
      emit({ t: 'ident', v: s, line }, start); continue;
    }
    if (c === '{' || c === '}' || c === ',' || c === '(' || c === ')' || c === '[' || c === ']' || c === ';') {
      i++; emit({ t: 'punct', v: c, line }, start); continue;
    }
    // Lenient: anything else (macro syntax like |, stray punctuation) becomes
    // an opaque token. It can never form an identifier/string/number, so it
    // can't create false value-assignment matches; structural mistakes still
    // surface as clear parser errors ("expected ...").
    i++; emit({ t: 'punct', v: c, line }, start); continue;
  }
  return toks;
}

function parseError(tok, msg) {
  const where = tok ? `line ${tok.line}` : 'end of input';
  return new Error(`values: ${msg} (${where})`);
}

function expectPunct(toks, i, v, what) {
  const t = toks[i];
  if (!t || t.t !== 'punct' || t.v !== v) throw parseError(t, `expected '${v}'${what ? ` ${what}` : ''}`);
  return i + 1;
}

function expectIdent(toks, i, what) {
  const t = toks[i];
  if (!t || t.t !== 'ident') throw parseError(t, `expected identifier${what ? ` ${what}` : ''}`);
  return { name: t.v, next: i + 1 };
}

/** Pack an MSB-first bit string ('1010') into a Buffer, zero-padding the tail. */
function packBits(s) {
  if (!/^[01]*$/.test(s)) throw new Error(`values: bad BIT STRING '${s}'`);
  const bytes = [];
  for (let k = 0; k < s.length; k += 8) {
    const chunk = s.slice(k, k + 8).padEnd(8, '0');
    bytes.push(parseInt(chunk, 2));
  }
  return Buffer.from(bytes);
}

/**
 * Read one value of the given resolved descriptor.
 * Returns { value, next } — the JS value and the index after it.
 */
function readValue(toks, i, registry, desc, ctx) {
  const tok = toks[i];
  const bad = (msg) => { throw parseError(tok, `${msg} (for ${ctx})`); };
  switch (desc.kind) {
    case 'integer': {
      if (!tok || tok.t !== 'number') bad(`expected a number, got ${tok ? `'${tok.v}'` : 'end of input'}`);
      return { value: tok.v, next: i + 1 };
    }
    case 'enumerated': {
      if (!tok || tok.t !== 'ident') bad('expected an enumeration symbol');
      if (desc.symbols && Object.prototype.hasOwnProperty.call(desc.symbols, tok.v)) {
        return { value: desc.symbols[tok.v], next: i + 1 };
      }
      bad(`unknown symbol '${tok.v}'`);
    }
    case 'boolean': {
      if (!tok || tok.t !== 'ident' || (tok.v !== 'TRUE' && tok.v !== 'FALSE')) bad("expected TRUE or FALSE");
      return { value: tok.v === 'TRUE', next: i + 1 };
    }
    case 'null': {
      if (!tok || tok.t !== 'ident' || tok.v !== 'NULL') bad('expected NULL');
      return { value: null, next: i + 1 };
    }
    case 'charstring': {
      if (!tok || tok.t !== 'string') bad('expected a quoted string');
      return { value: tok.v, next: i + 1 };
    }
    case 'octetstring': {
      if (!tok) bad('expected a string value');
      if (tok.t === 'string') return { value: Buffer.from(tok.v, 'utf8'), next: i + 1 };
      if (tok.t === 'hex') return { value: Buffer.from(tok.v, 'hex'), next: i + 1 };
      bad('expected "..." or \'...\'H');
    }
    case 'bitstring': {
      if (!tok) bad('expected a bit-string value');
      if (tok.t === 'bits') return { value: packBits(tok.v), next: i + 1 };
      if (tok.t === 'hex') return { value: Buffer.from(tok.v, 'hex'), next: i + 1 };
      bad("expected '...'B or '...'H");
    }
    case 'oid': {
      let j = expectPunct(toks, i, '{', 'to open the OID value');
      const arcs = [];
      for (;;) {
        const t = toks[j];
        if (!t) throw parseError(t, 'unterminated OID value');
        if (t.t === 'punct' && t.v === '}') { j++; break; }
        if (t.t === 'number') { arcs.push(t.v); j++; }
        else if (t.t === 'ident') { // name(number)
          j = expectPunct(toks, j + 1, '(', `after arc name '${t.v}'`);
          const n = toks[j];
          if (!n || n.t !== 'number') throw parseError(n, `expected arc number after '${t.v}('`);
          arcs.push(n.v); j++;
          j = expectPunct(toks, j, ')', 'to close the arc');
        } else throw parseError(t, 'expected an OID arc');
      }
      return { value: arcs.join('.'), next: j };
    }
    case 'time': {
      if (!tok || tok.t !== 'string') bad('expected a quoted time string');
      const d = new Date(tok.v);
      if (isNaN(d.getTime())) bad(`unparseable time '${tok.v}'`);
      return { value: d, next: i + 1 };
    }
    case 'sequence': {
      let j = expectPunct(toks, i, '{', 'to open the structure value');
      const out = {};
      const seen = new Set();
      for (;;) {
        const t = toks[j];
        if (!t) throw parseError(t, 'unterminated structure value');
        if (t.t === 'punct' && t.v === '}') { j++; break; }
        const { name, next } = expectIdent(toks, j, 'as a field name');
        const field = desc.fields.find((f) => f.name === name);
        if (!field) bad(`unknown field '${name}'`);
        if (seen.has(name)) bad(`duplicate field '${name}'`);
        seen.add(name);
        const r = readValue(toks, next, registry, registry.resolveType(field.typeRef), `${ctx}.${name}`);
        out[name] = r.value;
        j = r.next;
        const sep = toks[j];
        if (!sep) throw parseError(sep, 'unterminated structure value');
        if (sep.t === 'punct' && sep.v === ',') { j++; continue; }
        if (sep.t === 'punct' && sep.v === '}') { j++; break; }
        throw parseError(sep, "expected ',' or '}'");
      }
      return { value: out, next: j };
    }
    case 'choice': {
      let j = expectPunct(toks, i, '{', 'to open the choice value');
      const { name, next } = expectIdent(toks, j, 'as a choice alternative');
      const alt = desc.choices.find((a) => a.name === name);
      if (!alt) bad(`unknown alternative '${name}'`);
      const r = readValue(toks, next, registry, registry.resolveType(alt.typeRef), `${ctx}<${name}>`);
      j = expectPunct(toks, r.next, '}', 'to close the choice value');
      return { value: { choice: name, value: r.value }, next: j };
    }
    case 'sequenceOf':
    case 'setOf': {
      let j = expectPunct(toks, i, '{', 'to open the list value');
      const out = [];
      const elemDesc = registry.resolveType(desc.elementRef);
      for (;;) {
        const t = toks[j];
        if (!t) throw parseError(t, 'unterminated list value');
        if (t.t === 'punct' && t.v === '}') { j++; break; }
        const r = readValue(toks, j, registry, elemDesc, `${ctx}[${out.length}]`);
        out.push(r.value);
        j = r.next;
        const sep = toks[j];
        if (!sep) throw parseError(sep, 'unterminated list value');
        if (sep.t === 'punct' && sep.v === ',') { j++; continue; }
        if (sep.t === 'punct' && sep.v === '}') { j++; break; }
        throw parseError(sep, "expected ',' or '}'");
      }
      return { value: out, next: j };
    }
    default:
      throw new Error(`values: no value syntax for type kind '${desc.kind}' (${ctx})`);
  }
}

/**
 * Skip one value syntactically (no type info needed): a single token, or a
 * balanced {...} span. Returns the index just past the value.
 */
function skipValue(toks, i) {
  const t = toks[i];
  if (!t) throw parseError(t, 'unterminated value');
  if (t.t === 'punct' && t.v === '{') {
    let depth = 0;
    let j = i;
    for (;;) {
      const u = toks[j];
      if (!u) throw parseError(u, 'unterminated value');
      if (u.t === 'punct' && u.v === '{') depth++;
      if (u.t === 'punct' && u.v === '}') { depth--; if (depth === 0) return j + 1; }
      j++;
    }
  }
  return i + 1;
}

function moduleBodyStart(toks) {
  for (let k = 0; k + 3 < toks.length; k++) {
    if (toks[k].t === 'ident' && toks[k].v === 'DEFINITIONS' &&
        toks[k + 1].t === 'punct' && toks[k + 1].v === '::=' &&
        toks[k + 2].t === 'ident' && toks[k + 2].v === 'BEGIN') {
      return k + 3;
    }
  }
  return 0;
}

// ASN.1 reserved words that can never start a value assignment.
const KEYWORDS = new Set([
  'SEQUENCE', 'SET', 'CHOICE', 'OF', 'OPTIONAL', 'IMPLICIT', 'EXPLICIT',
  'ENUMERATED', 'DEFINITIONS', 'BEGIN', 'END', 'IMPORTS', 'EXPORTS', 'FROM',
  'TRUE', 'FALSE', 'NULL', 'TAGS', 'AUTOMATIC', 'EXTENSIBILITY', 'IMPLIED',
  'INSTRUCTIONS', 'WITH', 'SYNTAX', 'UNIVERSAL', 'APPLICATION', 'PRIVATE',
  'CONSTRAINED', 'BY', 'CONTAINING', 'ENCODED', 'COMPONENTS', 'SIZE',
  'FROM',
]);
// SMI macro invocations look like value assignments (`ifDescr OBJECT-TYPE
// ::= {...}`) but are schema, not data — never treat them as values.
const MACROS = new Set([
  'OBJECT-TYPE', 'MODULE-IDENTITY', 'OBJECT-IDENTITY', 'NOTIFICATION-TYPE',
  'TRAP-TYPE', 'TEXTUAL-CONVENTION', 'OBJECT-GROUP', 'NOTIFICATION-GROUP',
  'MODULE-COMPLIANCE', 'AGENT-CAPABILITIES',
]);

/**
 * Match `name Type Words ::= value` at toks[i]. X.680: a valuereference
 * starts with a lowercase letter, a typereference with an uppercase one —
 * so `Roster ::= SEQUENCE OF Message` can never match mid-body, no matter
 * what definition follows it. Returns { name, typeName, valueStart } or null.
 */
function matchValueAssign(toks, i) {
  const t = toks[i];
  if (!t || t.t !== 'ident') return null;
  if (!/^[a-z]/.test(t.v)) return null; // valuereference: lowercase first
  if (KEYWORDS.has(t.v)) return null;
  let j = i + 1;
  const words = [];
  while (toks[j] && toks[j].t === 'ident') {
    if (!/^[A-Z]/.test(toks[j].v)) return null; // typereference: uppercase first
    words.push(toks[j].v);
    j++;
  }
  if (words.length === 0) return null;
  // `x OBJECT IDENTIFIER ::= {...}` defines a namespace node (SMI idiom),
  // not a data value — it stays schema. (Named OID *types* still work as
  // value types: `arc MyArc ::= { 1 3 6 1 }`.)
  if (words[0] === 'DEFINITIONS' || words.join(' ') === 'OBJECT IDENTIFIER' || MACROS.has(words[0])) return null;
  if (!toks[j] || toks[j].t !== 'punct' || toks[j].v !== '::=') return null;
  return { name: t.v, typeName: words.join(' '), valueStart: j + 1, end: j };
}

const OPEN = new Set(['{', '[', '(']);
const CLOSE = new Set(['}', ']', ')']);

/** Shared module-body scan: calls visit(i) at each depth-0 token. */
function scanBody(toks, visit) {
  let i = moduleBodyStart(toks);
  let depth = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (t.t === 'ident' && t.v === 'END' && depth === 0) break;
    if (t.t === 'punct' && OPEN.has(t.v)) { depth++; i++; continue; }
    if (t.t === 'punct' && CLOSE.has(t.v)) { depth--; i++; continue; }
    if (depth === 0 && t.t === 'ident' &&
        toks[i + 1] && toks[i + 1].t === 'ident' && toks[i + 1].v === 'MACRO' &&
        toks[i + 2] && toks[i + 2].t === 'punct' && toks[i + 2].v === '::=') {
      // `Name MACRO ::= BEGIN ... END`: a syntax definition, never data.
      // Skip it whole — its `|`-alternatives would otherwise false-positive.
      let j = i + 3;
      while (j < toks.length && !(toks[j].t === 'ident' && toks[j].v === 'BEGIN')) j++;
      j++; // past BEGIN
      let d = 0;
      while (j < toks.length) {
        const u = toks[j];
        if (u.t === 'ident' && u.v === 'END' && d === 0) { j++; break; }
        if (u.t === 'punct' && OPEN.has(u.v)) d++;
        if (u.t === 'punct' && CLOSE.has(u.v)) d--;
        j++;
      }
      i = j;
      continue;
    }
    if (depth === 0) {
      const r = visit(toks, i);
      if (r) { i = r; continue; }
    }
    i++;
  }
}

/**
 * Remove all top-level `name Type ::= value` assignments from the text so
 * the schema remainder parses with asn2json. Returns the stripped text.
 */
function stripValueAssignments(text) {
  const toks = tokenize(text);
  const spans = [];
  scanBody(toks, (t, i) => {
    const m = matchValueAssign(t, i);
    if (!m) return 0;
    const end = skipValue(t, m.valueStart);
    spans.push([t[i].start, t[end - 1].end]);
    return end;
  });
  let out = text;
  for (let s = spans.length - 1; s >= 0; s--) {
    out = out.slice(0, spans[s][0]) + out.slice(spans[s][1]);
  }
  return out;
}

/**
 * Parse all top-level `name Type ::= value` assignments in the text.
 * Needs the registry to resolve type names while parsing.
 * Returns [{ name, typeName, value }].
 */
function parseValueAssignments(text, registry) {
  const toks = tokenize(text);
  const out = [];
  scanBody(toks, (t, i) => {
    const m = matchValueAssign(t, i);
    if (!m) return 0;
    const { name, typeName } = m;
    let desc;
    try {
      desc = registry.resolveType(typeName);
    } catch (e) {
      throw parseError(t[m.end], `value '${name}' names unknown type '${typeName}'`);
    }
    const r = readValue(t, m.valueStart, registry, desc, name);
    out.push({ name, typeName, value: r.value });
    return r.next;
  });
  return out;
}

module.exports = { tokenize, parseValueAssignments, stripValueAssignments, scanBody, matchValueAssign };
