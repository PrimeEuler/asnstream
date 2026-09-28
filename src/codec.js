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
      const block = new asn1js.Enumerated({ value: Number(value) });
      return applyTag(block, desc);
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
      return new asn1js.Sequence({
        value: desc.fields.map(f => encodeValue(registry, registry.resolveType(f.typeRef), value[f.name])),
      });
    }
    case 'choice': {
      if (!value || typeof value.choice !== 'string') {
        throw new TypeError(`CHOICE ${desc.name} needs { choice: <field>, value }`);
      }
      const field = desc.choices.find(c => c.name === value.choice);
      if (!field) throw new Error(`Unknown choice ${value.choice} for ${desc.name}`);
      return encodeValue(registry, registry.resolveType(field.typeRef), value.value);
    }
    case 'sequenceOf': {
      if (!Array.isArray(value)) throw new TypeError(`Expected array for ${desc.name}`);
      const el = registry.resolveType(desc.elementRef);
      return new asn1js.Sequence({ value: value.map(v => encodeValue(registry, el, v)) });
    }
    default:
      throw new Error(`Cannot encode kind ${desc.kind} (${desc.name})`);
  }
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
    case 'oid':
      return block.valueBlock.toString();
    case 'bitstring':
      return bytesOf(block);
    case 'sequence': {
      // Positional walk: child i corresponds to fields[i]. (compareSchema
      // attaches names to the compare *root* in a flat namespace, which
      // collides on nested sequences, so we never rely on it here.)
      const children = block.valueBlock.value || [];
      if (children.length !== desc.fields.length) {
        throw new Error(
          `Field count mismatch decoding ${desc.name}: got ${children.length}, want ${desc.fields.length}`
        );
      }
      const out = {};
      desc.fields.forEach((f, i) => {
        out[f.name] = decodeValue(registry, registry.resolveType(f.typeRef), children[i]);
      });
      return out;
    }
    case 'choice': {
      for (const c of desc.choices) {
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
    throw new Error(`Schema mismatch decoding ${typeName}: ${JSON.stringify(compared.result && compared.result.error)}`);
  }
  return decodeValue(registry, desc, compared.result);
}

module.exports = {
  encodeMessage,
  decodeMessage,
  encodeValue,
  decodeValue,
  buildSchema,
};
