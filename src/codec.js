'use strict';
/**
 * codec — encode JS values to BER and decode BER to JS values using
 * asn1js schema objects compiled from MIB type descriptors.
 *
 * JS mapping:
 *   INTEGER / Counter / Gauge / TimeTicks -> number
 *   OCTET STRING                          -> Buffer (DisplayString -> string)
 *   OBJECT IDENTIFIER                     -> '1.3.6.1...' string
 *   BOOLEAN                               -> boolean, NULL -> null
 *   BIT STRING                            -> Buffer
 *   SEQUENCE                              -> { field: value }
 *   CHOICE                                -> { choice: fieldName, value }
 *   SEQUENCE OF                           -> [ ... ]
 */
const asn1js = require('asn1js');

function toArrayBuffer(buf) {
  const b = Buffer.from(buf);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function intFromBytes(buf) {
  if (buf.length === 0) return 0;
  let v = 0n;
  for (const byte of buf) v = (v << 8n) | BigInt(byte);
  if (buf[0] & 0x80) v -= 1n << BigInt(buf.length * 8);
  if (v <= BigInt(Number.MAX_SAFE_INTEGER) && v >= BigInt(Number.MIN_SAFE_INTEGER)) return Number(v);
  return v;
}

function checkRange(desc, value, what) {
  const c = desc.constraints;
  if (!c) return;
  const range = c.SIZE || (c.min !== undefined ? c : null);
  if (range && (value < range.min || value > range.max)) {
    throw new RangeError(`${what}: ${value} outside [${range.min}, ${range.max}]`);
  }
}

function applyTag(block, desc) {
  if (desc.tagClass && desc.tagClass !== 1) {
    block.idBlock.tagClass = desc.tagClass;
    block.idBlock.tagNumber = desc.tagNumber;
  }
  return block;
}

function encodeValue(registry, desc, value) {
  switch (desc.kind) {
    case 'integer': {
      if (typeof value !== 'number' && typeof value !== 'bigint') {
        throw new TypeError(`Expected number for ${desc.name}, got ${typeof value}`);
      }
      checkRange(desc, Number(value), desc.name);
      const block = new asn1js.Integer({ value: Number(value) });
      return applyTag(block, desc);
    }
    case 'enumerated': {
      let num = value;
      if (typeof value === 'string') {
        if (!desc.symbols || desc.symbols[value] === undefined) {
          throw new Error(`Unknown enumerator '${value}' for ${desc.name}`);
        }
        num = desc.symbols[value];
      }
      const block = new asn1js.Enumerated({ value: Number(num) });
      return applyTag(block, desc);
    }
    case 'charstring': {
      const text = String(value);
      checkRange(desc, text.length, desc.name);
      const Cls = asn1js[desc.stringType];
      if (!Cls) throw new Error(`asn1js has no ${desc.stringType} for ${desc.name}`);
      return applyTag(new Cls({ value: text }), desc);
    }
    case 'time': {
      const Cls = asn1js[desc.timeType];
      if (!Cls) throw new Error(`asn1js has no ${desc.timeType} for ${desc.name}`);
      return applyTag(new Cls({ valueDate: toDate(value, desc.name) }), desc);
    }
    case 'boolean':
      return new asn1js.Boolean({ value: Boolean(value) });
    case 'null':
      return new asn1js.Null();
    case 'octetstring': {
      const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
      checkRange(desc, bytes.length, desc.name);
      const block = new asn1js.OctetString({ valueHex: bytes });
      return applyTag(block, desc);
    }
    case 'oid':
      return new asn1js.ObjectIdentifier({ value: String(value) });
    case 'bitstring': {
      const bytes = Buffer.from(value);
      return new asn1js.BitString({ valueHex: bytes });
    }
    case 'sequence': {
      if (value === null || typeof value !== 'object') {
        throw new TypeError(`Expected object for SEQUENCE ${desc.name}`);
      }
      const parts = [];
      for (const f of desc.fields) {
        const v = value[f.name];
        if (v === undefined) {
          // Absent OPTIONAL fields are omitted. Untagged, this is only
          // unambiguous for *trailing* optionals; explicitly tagged
          // optionals may sit anywhere (matched by tag on decode).
          if (f.optional) continue;
          throw new TypeError(`Missing required field ${f.name} for SEQUENCE ${desc.name}`);
        }
        parts.push(encodeField(registry, desc.name, f, v));
      }
      return new asn1js.Sequence({ value: parts });
    }
    case 'choice': {
      if (!value || typeof value.choice !== 'string') {
        throw new TypeError(`CHOICE ${desc.name} needs { choice: <field>, value }`);
      }
      const field = desc.choices.find(c => c.name === value.choice);
      if (!field) throw new Error(`Unknown choice ${value.choice} for ${desc.name}`);
      return encodeField(registry, desc.name, field, value.value);
    }
    case 'sequenceOf': {
      if (!Array.isArray(value)) throw new TypeError(`Expected array for ${desc.name}`);
      const el = registry.resolveType(desc.elementRef);
      return new asn1js.Sequence({ value: value.map(v => encodeValue(registry, el, v)) });
    }
    case 'setOf': {
      if (!Array.isArray(value)) throw new TypeError(`Expected array for ${desc.name}`);
      const el = registry.resolveType(desc.elementRef);
      return new asn1js.Set({ value: value.map(v => encodeValue(registry, el, v)) });
    }
    default:
      throw new Error(`Cannot encode kind ${desc.kind} (${desc.name})`);
  }
}

// Encode one SEQUENCE/CHOICE field, applying its explicit [n] tag when
// present. IMPLICIT replaces the inner tag; EXPLICIT wraps the inner
// encoding in a constructed context-tagged block.
function encodeField(registry, typeName, f, value) {
  const innerDesc = registry.resolveType(f.typeRef);
  const inner = encodeValue(registry, innerDesc, value);
  if (f.tagNumber === undefined) return inner;
  if (f.implicit) {
    inner.idBlock.tagClass = f.tagClass;
    inner.idBlock.tagNumber = f.tagNumber;
    return inner;
  }
  return new asn1js.Constructed({
    idBlock: { tagClass: f.tagClass, tagNumber: f.tagNumber },
    value: [inner],
  });
}

// Decode one tagged field: unwrap EXPLICIT, or re-parse IMPLICIT content
// under the inner type's universal tag (asn1js leaves context-tagged
// primitives unparsed, so we rebuild the TLV and parse it fresh).
function decodeField(registry, typeName, f, block) {
  const innerDesc = registry.resolveType(f.typeRef);
  if (f.tagNumber !== undefined && !f.implicit) {
    const kids = block.valueBlock.value || [];
    if (kids.length !== 1) throw new Error(`Bad EXPLICIT wrapper for ${typeName}.${f.name}`);
    return decodeValue(registry, innerDesc, kids[0]);
  }
  if (f.tagNumber !== undefined) {
    return decodeValue(registry, innerDesc, reparseImplicit(block, innerDesc));
  }
  return decodeValue(registry, innerDesc, block);
}

const UNIVERSAL_TAGS = {
  boolean: 1, integer: 2, bitstring: 3, octetstring: 4, null: 5, oid: 6,
  enumerated: 10,
  sequence: 16, set: 17, sequenceOf: 16, setOf: 17, choice: -1, // choice: no single tag
  charstring: {
    Utf8String: 12, BmpString: 30, UniversalString: 28, PrintableString: 19,
    IA5String: 22, VisibleString: 26, NumericString: 18, TeletexString: 20,
    GeneralString: 27,
  },
  time: { UTCTime: 23, GeneralizedTime: 24 },
};

function universalTagNumber(desc) {
  if (desc.kind === 'charstring') return UNIVERSAL_TAGS.charstring[desc.stringType];
  if (desc.kind === 'time') return UNIVERSAL_TAGS.time[desc.timeType];
  return UNIVERSAL_TAGS[desc.kind];
}

function encodeLength(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function reparseImplicit(block, desc) {
  const tagNo = universalTagNumber(desc);
  if (tagNo === undefined || tagNo < 0 || tagNo > 30) {
    throw new Error(`Cannot IMPLICIT-decode kind ${desc.kind} (${desc.name})`);
  }
  // Generic context-tagged blocks don't retain valueHexView; constructed
  // ones keep parsed children, so re-encode them for the content octets.
  const content = block.idBlock.isConstructed
    ? Buffer.concat((block.valueBlock.value || []).map(k => Buffer.from(k.toBER(false))))
    : bytesOf(block);
  const first = (block.idBlock.isConstructed ? 0x20 : 0x00) | tagNo;
  const tlv = Buffer.concat([Buffer.from([first]), encodeLength(content.length), content]);
  const parsed = asn1js.fromBER(toArrayBuffer(tlv));
  if (parsed.offset === -1) throw new Error(`Reparse failed for IMPLICIT ${desc.name}`);
  return parsed.result;
}

// --- time helpers: asn1js parses time *to* BER but not back, so the codec
// owns both directions between Date and the wire string. ---
function toDate(value, what) {
  if (value instanceof Date) return value;
  const d = new Date(value);
  if (isNaN(d.getTime())) throw new TypeError(`Expected Date for ${what}, got ${value}`);
  return d;
}

function parseTime(desc, bytes) {
  const s = bytes.toString('ascii').trim();
  let m;
  if (desc.timeType === 'UTCTime') {
    // YYMMDDHHMMSSZ — years 00-49 map to 2000s, 50-99 to 1900s (X.680).
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`Cannot parse UTCTime '${s}'`);
    const yy = Number(m[1]);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  // GeneralizedTime: YYYYMMDDHHMMSS[.frac]Z — fractional part ignored.
  m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
  if (!m) throw new Error(`Cannot parse GeneralizedTime '${s}'`);
  return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
}

function buildSchema(registry, desc, name) {
  const params = name ? { name } : {};
  let block;
  switch (desc.kind) {
    case 'integer': block = new asn1js.Integer(params); break;
    case 'enumerated': block = new asn1js.Enumerated(params); break;
    case 'boolean': block = new asn1js.Boolean(params); break;
    case 'null': block = new asn1js.Null(params); break;
    case 'octetstring': block = new asn1js.OctetString(params); break;
    case 'oid': block = new asn1js.ObjectIdentifier(params); break;
    case 'bitstring': block = new asn1js.BitString(params); break;
    case 'charstring': {
      const Cls = asn1js[desc.stringType];
      if (!Cls) throw new Error(`asn1js has no ${desc.stringType} for ${desc.name}`);
      block = new Cls(params);
      break;
    }
    case 'time': {
      const Cls = asn1js[desc.timeType];
      if (!Cls) throw new Error(`asn1js has no ${desc.timeType} for ${desc.name}`);
      block = new Cls(params);
      break;
    }
    case 'sequence':
      block = new asn1js.Sequence(Object.assign(params, {
        value: desc.fields.map(f => buildSchema(registry, registry.resolveType(f.typeRef), f.name)),
      }));
      break;
    case 'choice':
      // A CHOICE matches if any alternative matches; wrap alternatives and
      // detect which named child survived by re-running compare per alternative.
      block = new asn1js.Choice({
        value: desc.choices.map(c => buildSchema(registry, registry.resolveType(c.typeRef), c.name)),
      });
      if (name) block.name = name;
      block.choiceAlternatives = desc.choices.map(c => c.name);
      break;
    case 'sequenceOf': {
      const el = registry.resolveType(desc.elementRef);
      block = new asn1js.Repeated({ name: name || 'items', value: buildSchema(registry, el) });
      break;
    }
    case 'setOf': {
      const el = registry.resolveType(desc.elementRef);
      block = new asn1js.Set(Object.assign(params, {
        value: [new asn1js.Repeated({ value: buildSchema(registry, el) })],
      }));
      break;
    }
    default:
      throw new Error(`Cannot build schema for kind ${desc.kind} (${desc.name})`);
  }
  return applyTag(block, desc);
}

function bytesOf(block) {
  const vb = block.valueBlock;
  const view = vb.valueHexView || vb.valueHex;
  return view ? Buffer.from(view) : Buffer.alloc(0);
}

function decodeValue(registry, desc, block) {
  switch (desc.kind) {
    case 'integer': {
      const v = block.valueBlock.valueDec;
      return v !== undefined ? v : intFromBytes(bytesOf(block));
    }
    case 'enumerated': {
      const v = block.valueBlock.valueDec;
      return v !== undefined ? v : intFromBytes(bytesOf(block));
    }
    case 'boolean':
      return Boolean(block.valueBlock.value);
    case 'null':
      return null;
    case 'octetstring': {
      const bytes = bytesOf(block);
      return desc.smi === 'DisplayString' ? bytes.toString('utf8') : bytes;
    }
    case 'charstring':
      return String(block.valueBlock.value);
    case 'time':
      return parseTime(desc, bytesOf(block));
    case 'oid':
      return block.valueBlock.toString();
    case 'bitstring':
      return bytesOf(block);
    case 'sequence': {
      // Tagged fields match by (tagClass, tagNumber); untagged fields match
      // positionally among the remaining children. Trailing untagged
      // OPTIONALs may be absent. An untagged optional ahead of present
      // fields is ambiguous in BER and rejected at encode time by
      // convention — decode reads it positionally (documented limitation).
      const children = block.valueBlock.value || [];
      const used = new Array(children.length).fill(false);
      const out = {};
      const tagOf = (b) => [b.idBlock.tagClass, b.idBlock.tagNumber];
      for (const f of desc.fields) {
        if (f.tagNumber === undefined) continue;
        const idx = children.findIndex((c, i) =>
          !used[i] && c.idBlock.tagClass === f.tagClass && c.idBlock.tagNumber === f.tagNumber);
        if (idx === -1) {
          if (f.optional) { out[f.name] = undefined; continue; }
          throw new Error(`Missing required tagged field ${f.name} decoding ${desc.name}`);
        }
        used[idx] = true;
        out[f.name] = decodeField(registry, desc.name, f, children[idx]);
      }
      const rest = children.filter((_, i) => !used[i]);
      let ci = 0;
      for (const f of desc.fields) {
        if (f.tagNumber !== undefined) continue;
        if (ci >= rest.length) {
          if (!f.optional) throw new Error(`Missing required field ${f.name} decoding ${desc.name}`);
          out[f.name] = undefined;
          continue;
        }
        out[f.name] = decodeValue(registry, registry.resolveType(f.typeRef), rest[ci++]);
      }
      if (ci < rest.length) {
        throw new Error(
          `Field count mismatch decoding ${desc.name}: got ${children.length}, want ${desc.fields.length}`
        );
      }
      return out;
    }
    case 'choice': {
      for (const c of desc.choices) {
        // A CHOICE alternative's encoding *is* the block itself; tagged
        // alternatives match by tag, untagged ones by schema probe.
        if (c.tagNumber !== undefined) {
          if (block.idBlock.tagClass === c.tagClass && block.idBlock.tagNumber === c.tagNumber) {
            return { choice: c.name, value: decodeField(registry, desc.name, c, block) };
          }
          continue;
        }
        // compareSchema on a Choice returns root; probe each alternative schema.
        const alt = buildSchema(registry, registry.resolveType(c.typeRef));
        const r = asn1js.compareSchema(block, block, alt);
        if (r.verified) {
          return { choice: c.name, value: decodeValue(registry, registry.resolveType(c.typeRef), block) };
        }
      }
      throw new Error(`No CHOICE alternative matched for ${desc.name}`);
    }
    case 'sequenceOf': {
      const el = registry.resolveType(desc.elementRef);
      const items = block.valueBlock.value || [];
      return items.map(item => decodeValue(registry, el, item));
    }
    case 'setOf': {
      // A decoded Set's children arrive in wire order; we keep that order
      // rather than re-sorting (DER sorting is an encoder concern).
      const el = registry.resolveType(desc.elementRef);
      const items = block.valueBlock.value || [];
      return items.map(item => decodeValue(registry, el, item));
    }
    default:
      throw new Error(`Cannot decode kind ${desc.kind} (${desc.name})`);
  }
}

/** Encode a JS value as BER for a named MIB type. Returns a Buffer. */
function encodeMessage(registry, typeName, value) {
  const desc = registry.resolveType(typeName);
  const block = encodeValue(registry, desc, value);
  return Buffer.from(block.toBER(false));
}

/** Decode a BER buffer into a JS value for a named MIB type. */
function decodeMessage(registry, typeName, buffer) {
  const desc = registry.resolveType(typeName);
  const schema = buildSchema(registry, desc);
  const parsed = asn1js.fromBER(toArrayBuffer(buffer));
  if (parsed.offset === -1) throw new Error(`BER parse failed for ${typeName}`);
  const compared = asn1js.compareSchema(parsed.result, parsed.result, schema);
  if (!compared.verified) {
    // compareSchema is tag- and arity-strict: it rejects sequences with
    // absent OPTIONAL fields, explicitly tagged fields, SET OF wrappers,
    // and (at any nesting depth) CHOICEs with tagged alternatives. Those
    // shapes still get a structural decode — decodeValue enforces field
    // presence itself.
    if (!needsStructuralDecode(registry, desc)) {
      throw new Error(`Schema mismatch decoding ${typeName}: ${JSON.stringify(compared.result && compared.result.error)}`);
    }
    return decodeValue(registry, desc, parsed.result);
  }
  return decodeValue(registry, desc, compared.result);
}

/**
 * True when the type's shape needs the structural decoder: anything
 * compareSchema is strict about — OPTIONALs, [n] tags, tagged CHOICE
 * alternatives, SET OF — at any nesting depth.
 */
function needsStructuralDecode(registry, desc, seen = new Set()) {
  if (!desc || typeof desc.name !== 'string' || seen.has(desc.name)) return false;
  seen.add(desc.name);
  const inner = (ref) => {
    try { return needsStructuralDecode(registry, registry.resolveType(ref), seen); }
    catch { return false; }
  };
  if (desc.kind === 'sequence') {
    return desc.fields.some((f) =>
      f.optional || f.tagNumber !== undefined || inner(f.typeRef));
  }
  if (desc.kind === 'choice') {
    return desc.choices.some((c) =>
      c.tagNumber !== undefined || inner(c.typeRef));
  }
  return desc.kind === 'setOf';
}

module.exports = {
  encodeMessage,
  decodeMessage,
  encodeValue,
  decodeValue,
  buildSchema,
};
