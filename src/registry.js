'use strict';
/**
 * MibRegistry — loads SNMP MIB modules through asn2json and exposes a
 * resolved view: named types, OBJECT-TYPE entries, and the OID tree.
 *
 * The asn2json IR uses shapes like:
 *   { SEQUENCE: [ [fieldName, typeRef], ... ] }
 *   { CHOICE:   [ [fieldName, typeRef], ... ] }
 *   { 'OBJECT-TYPE': { SYNTAX: typeRef, ACCESS, STATUS, DESCRIPTION, '::=': [parent, subId] } }
 *   { 'OBJECT IDENTIFIER': { '::=': [parent, subId] } }
 *   { tag: { class: 'APPLICATION', number: 1 }, definition: 'IMPLICIT', type: [...] }
 *   "SomeAlias": "OCTET STRING"              (plain string alias)
 * where typeRef is a name string or [name, constraints].
 */
const asn2json = require('asn2json');
const fs = require('fs');

// Well-known SMI roots, as full dotted OIDs, for parent-chain resolution.
const WELL_KNOWN_ROOTS = { root: '', iso: '1', org: '1.3', dod: '1.3.6' };

const TAG_CLASSES = { UNIVERSAL: 1, APPLICATION: 2, CONTEXT: 3, PRIVATE: 4 };

// Built-in ASN.1 types every module can reference without defining.
// Character strings and time types decode to JS strings / Dates.
const BUILTINS = {
  'INTEGER':           { kind: 'integer' },
  'BOOLEAN':           { kind: 'boolean' },
  'NULL':              { kind: 'null' },
  'OCTET STRING':      { kind: 'octetstring' },
  'OBJECT IDENTIFIER': { kind: 'oid' },
  'BIT STRING':        { kind: 'bitstring' },
  'ENUMERATED':        { kind: 'enumerated' },
  'UTF8String':        { kind: 'charstring', stringType: 'Utf8String' },
  'PrintableString':   { kind: 'charstring', stringType: 'PrintableString' },
  'IA5String':         { kind: 'charstring', stringType: 'IA5String' },
  'VisibleString':     { kind: 'charstring', stringType: 'VisibleString' },
  'NumericString':     { kind: 'charstring', stringType: 'NumericString' },
  'BMPString':         { kind: 'charstring', stringType: 'BmpString' },
  'UniversalString':   { kind: 'charstring', stringType: 'UniversalString' },
  'TeletexString':     { kind: 'charstring', stringType: 'TeletexString' },
  'GeneralString':     { kind: 'charstring', stringType: 'GeneralString' },
  'UTCTime':           { kind: 'time', timeType: 'UTCTime' },
  'GeneralizedTime':   { kind: 'time', timeType: 'GeneralizedTime' },
};

// SMIv1/v2 application types not always spelled out in every MIB.
const SMI_FALLBACK = {
  'Counter':     { kind: 'integer', tagClass: 2, tagNumber: 1, implicit: true },
  'Counter32':   { kind: 'integer', tagClass: 2, tagNumber: 1, implicit: true },
  'Gauge':       { kind: 'integer', tagClass: 2, tagNumber: 2, implicit: true },
  'Gauge32':     { kind: 'integer', tagClass: 2, tagNumber: 2, implicit: true },
  'TimeTicks':   { kind: 'integer', tagClass: 2, tagNumber: 3, implicit: true },
  'Opaque':      { kind: 'octetstring', tagClass: 2, tagNumber: 4, implicit: true },
  'IpAddress':   { kind: 'octetstring', tagClass: 2, tagNumber: 0, implicit: true },
  'NetworkAddress': { kind: 'choice', note: 'IpAddress only in practice' },
};

/**
 * Normalize asn2json's SEQUENCE/CHOICE member list: a single-field type
 * comes back as one bare tuple ["name", typeRef], multi-field as an array
 * of tuples. A tuple always starts with the member name string.
 */
function asTuples(members) {
  if (!Array.isArray(members)) return [];
  if (members.length > 0 && typeof members[0] === 'string') return [members];
  return members;
}

class MibRegistry {
  constructor() {
    this.modules = {};          // moduleName -> DEFINITIONS object
    this.defs = new Map();      // type/object name -> { module, def }
    this._oidCache = new Map(); // name -> dotted OID
    this._typeCache = new Map();// name -> resolved descriptor
    this._oidToType = new Map();// dotted OID -> message type name
    this._typeToOid = new Map();// message type name -> dotted OID
    this._assignedOids = new Map(); // name -> explicitly/auto-assigned OID
  }

  loadFile(filePath, moduleName) {
    return this.loadText(fs.readFileSync(filePath, 'utf8'), moduleName || filePath);
  }

  loadText(text, moduleName) {
    const parser = new asn2json();
    const parsed = parser.parse(text);
    for (const mod of Object.keys(parsed)) {
      const name = moduleName || mod;
      const defs = parsed[mod].DEFINITIONS || parsed[mod];
      this.modules[name] = defs;
      for (const key of Object.keys(defs)) {
        if (key === 'IMPORTS' || key === 'EXPORTS') continue;
        if (!this.defs.has(key)) this.defs.set(key, { module: name, def: defs[key] });
      }
    }
    this._oidCache.clear();
    this._typeCache.clear();
    this._oidToType.clear();
    return this;
  }

  /** Raw IR definition for a name, or undefined. */
  define(name) {
    const hit = this.defs.get(name);
    return hit ? hit.def : undefined;
  }

  /** Dotted OID for a named node, e.g. '1.3.6.1.2.1.2.2.1.2'. Pass-through for dotted input. */
  oidOf(name) {
    if (/^[0-9]+(\.[0-9]+)*$/.test(name)) return name;
    if (this._assignedOids.has(name)) return this._assignedOids.get(name);
    if (this._oidCache.has(name)) return this._oidCache.get(name);
    const oid = this._resolveOid(name, new Set());
    this._oidCache.set(name, oid);
    return oid;
  }

  /**
   * Pin an OID onto a named type that has no SMI '::=' assignment —
   * the bridge that lets arbitrary ASN.1 types ride the OID-tagged wire.
   */
  setTypeOid(name, oid) {
    if (!/^[0-9]+(\.[0-9]+)*$/.test(oid)) throw new Error(`Not a dotted OID: ${oid}`);
    if (!this.defs.has(name) && !BUILTINS[name]) throw new Error(`Unknown type: ${name}`);
    this._assignedOids.set(name, oid);
    this._oidToType.clear();
    this._typeToOid.clear();
    return this;
  }

  /**
   * Assign OIDs to every named definition that lacks one, sequentially
   * under the given base arc (sorted by name, so the mapping is stable
   * for a fixed schema). Types that already resolve to an OID keep theirs.
   */
  autoAssignOids(base) {
    if (!/^[0-9]+(\.[0-9]+)*$/.test(base)) throw new Error(`Not a dotted OID arc: ${base}`);
    let n = 1;
    for (const name of [...this.defs.keys()].sort()) {
      if (this._assignedOids.has(name)) continue;
      try { this.oidOf(name); continue; } catch { /* needs assignment */ }
      this._assignedOids.set(name, `${base}.${n++}`);
    }
    this._oidToType.clear();
    this._typeToOid.clear();
    return this;
  }

  _resolveOid(name, seen) {
    if (WELL_KNOWN_ROOTS[name] !== undefined) return WELL_KNOWN_ROOTS[name];
    if (/^[0-9]+$/.test(name)) return name;
    if (seen.has(name)) throw new Error(`OID parent cycle at ${name}`);
    seen.add(name);
    const def = this.define(name);
    if (!def) throw new Error(`Unknown MIB node: ${name}`);
    let path = null;
    if (def['OBJECT IDENTIFIER'] && def['OBJECT IDENTIFIER']['::=']) path = def['OBJECT IDENTIFIER']['::='];
    else if (def['OBJECT-TYPE'] && def['OBJECT-TYPE']['::=']) path = def['OBJECT-TYPE']['::='];
    else if (Array.isArray(def['::='])) path = def['::='];
    if (!path) throw new Error(`No OID assignment for ${name}`);
    // '::=' is an OID *path*: ['mgmt', 2] or ['iso', ['org', 3], ['dod', 6], 1].
    // Bare numbers append; [name, subId] appends subId (name is documentary);
    // a leading name expands to that node's full OID.
    const nums = [];
    path.forEach((el, idx) => {
      if (typeof el === 'number') nums.push(el);
      else if (Array.isArray(el)) {
        if (idx === 0) nums.push(...this._nameToNums(String(el[0]), seen));
        nums.push(el[1]);
      } else if (idx === 0) {
        nums.push(...this._nameToNums(String(el), seen));
      } else {
        throw new Error(`Bare name ${el} mid-path resolving ${name}`);
      }
    });
    return nums.join('.');
  }

  _nameToNums(name, seen) {
    return this._resolveOid(name, seen).split('.').filter(s => s !== '').map(Number);
  }

  /**
   * Resolve a type reference (name string or [name, constraints]) to a
   * normalized descriptor used by the schema compiler.
   */
  resolveType(typeRef) {
    // Inline constructed refs (['SEQUENCE OF', elem]) bypass the name cache.
    if (Array.isArray(typeRef) && (typeRef[0] === 'SEQUENCE OF' || typeRef[0] === 'SET OF')) {
      return this._resolveTypeRef(typeRef, new Set());
    }
    const [name, constraints] = Array.isArray(typeRef) ? typeRef : [typeRef, undefined];
    const cacheKey = constraints ? `${name}#${JSON.stringify(constraints)}` : name;
    if (this._typeCache.has(cacheKey)) return this._typeCache.get(cacheKey);
    const desc = this._resolveType(name, new Set());
    if (constraints) desc.constraints = Object.assign({}, desc.constraints, constraints);
    // OBJECT-TYPE SYNTAX refs carry SMI tags from the defining module already.
    this._typeCache.set(cacheKey, desc);
    return desc;
  }

  _resolveType(name, seen) {
    if (BUILTINS[name]) return Object.assign({ name, smi: name }, BUILTINS[name]);
    if (seen.has(name)) throw new Error(`Type cycle at ${name}`);
    seen.add(name);
    const def = this.define(name);

    if (def === undefined) {
      if (SMI_FALLBACK[name]) return Object.assign({ name, smi: name }, SMI_FALLBACK[name]);
      throw new Error(`Unknown type: ${name}`);
    }

    // Top-level 'Roster ::= SEQUENCE OF Message' comes back as a bare
    // array ['SEQUENCE OF', elem] (SET OF as { 'SET OF': elem }).
    if (Array.isArray(def) && (def[0] === 'SEQUENCE OF' || def[0] === 'SET OF')) {
      return { name, smi: name, kind: def[0] === 'SEQUENCE OF' ? 'sequenceOf' : 'setOf', elementRef: def[1] };
    }

    // Plain alias: "DisplayString": "OCTET STRING" (or another type name).
    if (typeof def === 'string') {
      const inner = this._resolveType(def, seen);
      return Object.assign({}, inner, { name, smi: name });
    }

    // SMI tagged type: { tag: { class, number }, definition: 'IMPLICIT', type: [...] }
    if (def.tag) {
      const inner = this._resolveTypeRef(def.type, seen);
      return Object.assign({}, inner, {
        name, smi: name,
        tagClass: TAG_CLASSES[def.tag.class] || 1,
        tagNumber: def.tag.number,
        implicit: def.definition !== 'EXPLICIT',
      });
    }

    if (def.SEQUENCE) {
      const fields = asTuples(def.SEQUENCE).map((tuple) => this._fieldTuple(tuple, name));
      // Untagged OPTIONALs are only unambiguous at the tail: a short wire
      // tail decodes as absent trailing optionals. After the first untagged
      // OPTIONAL, every later field must carry an explicit [n] tag —
      // otherwise a present field would land in the absent optional's slot.
      // Fail fast with a clear message, not a silent mis-decode.
      let seenUntaggedOptional = false;
      for (const f of fields) {
        if (seenUntaggedOptional && f.tagNumber === undefined) {
          throw new Error(
            `SEQUENCE ${name}: untagged OPTIONAL followed by untagged field '${f.name}' — ` +
            `ambiguous in BER. Give later fields explicit [n] tags.`
          );
        }
        if (f.optional && f.tagNumber === undefined) seenUntaggedOptional = true;
      }
      return { name, smi: name, kind: 'sequence', fields };
    }
    if (def.CHOICE) {
      return {
        name, smi: name, kind: 'choice',
        choices: asTuples(def.CHOICE).map((tuple) => this._fieldTuple(tuple, name)),
      };
    }
    if (def['SEQUENCE OF']) {
      return { name, smi: name, kind: 'sequenceOf', elementRef: def['SEQUENCE OF'] };
    }
    if (def['SET OF']) {
      return { name, smi: name, kind: 'setOf', elementRef: def['SET OF'] };
    }
    if (def.ENUMERATED) {
      // asn2json IR: { "0": "away", "1": "online", ... } (number -> name)
      const symbols = {};
      for (const [num, sym] of Object.entries(def.ENUMERATED)) symbols[sym] = Number(num);
      return { name, smi: name, kind: 'enumerated', symbols };
    }
    // OBJECT-TYPE used as a type ref: resolve through its SYNTAX.
    if (def['OBJECT-TYPE'] && def['OBJECT-TYPE'].SYNTAX) {
      const inner = this._resolveTypeRef(def['OBJECT-TYPE'].SYNTAX, seen);
      return Object.assign({}, inner, { name, smi: name, objectType: true });
    }
    throw new Error(`Cannot resolve type ${name}: unrecognized definition shape`);
  }

  /**
   * Normalize an asn2json field/alternative tuple:
   *   [name, typeRef] | [name, typeRef, 'OPTIONAL'] |
   *   [name, { tag: { class, number }, definition, type }, 'OPTIONAL']
   * A bare [n] tag defaults to CONTEXT-SPECIFIC, per X.680. Anonymous inline
   * types ({ SEQUENCE: [...] } as the type) are registered under a
   * synthesized `Owner.field` name so the rest of the machinery — codec,
   * proxy, OID index — sees only named types.
   */
  _fieldTuple(tuple, ownerName) {
    const [fname, ftype, ...rest] = tuple;
    const field = {
      name: fname,
      typeRef: ftype,
      optional: rest.includes('OPTIONAL') || rest.includes('DEFAULT'),
      tagClass: undefined,
      tagNumber: undefined,
      implicit: true,
    };
    let inner = ftype;
    if (ftype && typeof ftype === 'object' && ftype.tag) {
      inner = ftype.type;
      field.tagClass = ftype.tag.class ? (TAG_CLASSES[ftype.tag.class] || 3) : 3;
      field.tagNumber = ftype.tag.number;
      field.implicit = ftype.definition !== 'EXPLICIT';
    }
    if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
      const synth = `${ownerName || 'Anonymous'}$${fname}`;
      if (!this.defs.has(synth)) this.defs.set(synth, { module: 'inline', def: inner });
      field.typeRef = synth;
    } else {
      field.typeRef = inner;
    }
    return field;
  }

  _resolveTypeRef(typeRef, seen) {
    // Inline constructed refs: ['SEQUENCE OF', elemType] / ['SET OF', elemType].
    // (Plain [name, constraints] pairs are handled by resolveType.)
    if (Array.isArray(typeRef) && (typeRef[0] === 'SEQUENCE OF' || typeRef[0] === 'SET OF')) {
      const kind = typeRef[0] === 'SEQUENCE OF' ? 'sequenceOf' : 'setOf';
      return { name: typeRef[0], kind, elementRef: typeRef[1] };
    }
    const [name, constraints] = Array.isArray(typeRef) ? typeRef : [typeRef, undefined];
    const desc = this._resolveType(name, seen);
    if (constraints) desc.constraints = Object.assign({}, desc.constraints, constraints);
    return desc;
  }

  /** OBJECT-TYPE metadata for a named object (access, status, description, OID). */
  objectInfo(name) {
    const def = this.define(name);
    if (!def || !def['OBJECT-TYPE']) throw new Error(`Not an OBJECT-TYPE: ${name}`);
    const ot = def['OBJECT-TYPE'];
    return {
      name,
      oid: this.oidOf(name),
      syntax: ot.SYNTAX,
      access: ot.ACCESS,
      status: ot.STATUS,
      description: Array.isArray(ot.DESCRIPTION) ? ot.DESCRIPTION.join(' ') : ot.DESCRIPTION,
    };
  }

  /**
   * OID of the OBJECT-TYPE whose SYNTAX is the named message type —
   * e.g. oidOfType('IfEntry') -> the ifEntry row OID. Falls back to a node
   * with the exact name (for scalar objects used as their own type).
   */
  oidOfType(typeName) {
    if (this._oidToType.size === 0) this._buildOidIndex();
    const hit = this._typeToOid.get(typeName);
    if (hit) return hit;
    return this.oidOf(typeName);
  }
  /**
   * Message type name for a dotted OID — the SYNTAX type of the OBJECT-TYPE
   * carrying that OID. Builds the reverse index lazily.
   */
  typeOfOid(oid) {
    if (this._oidToType.size === 0) this._buildOidIndex();
    const hit = this._oidToType.get(oid);
    if (!hit) throw new Error(`No registered message type for OID ${oid}`);
    return hit;
  }

  _buildOidIndex() {
    const entries = [];
    for (const [name] of this.defs) {
      let oid;
      try { oid = this.oidOf(name); } catch { continue; }
      if (!/^[0-9.]+$/.test(oid)) continue;
      const def = this.define(name);
      if (!def) continue;
      if (def['OBJECT-TYPE'] && def['OBJECT-TYPE'].SYNTAX) {
        const syn = def['OBJECT-TYPE'].SYNTAX;
        const sname = Array.isArray(syn) ? syn[0] : syn;
        // Exact SYNTAX matches win over SEQUENCE OF table wrappers: a table's
        // OID must not claim its row type. ifTable (SEQUENCE OF IfEntry) only
        // fills gaps left by the ifEntry row object itself.
        const exact = sname !== 'SEQUENCE OF';
        entries.push({ oid, typeName: exact ? sname : syn[1], exact });
      } else {
        // Plain ASN.1 type with an OID (SMI '::=' node or assigned via
        // setTypeOid/autoAssignOids): the type name is its own message type.
        entries.push({ oid, typeName: name, exact: true });
      }
    }
    for (const pass of [true, false]) {
      for (const { oid, typeName, exact } of entries) {
        if (exact !== pass) continue;
        if (!this._oidToType.has(oid)) this._oidToType.set(oid, typeName);
        if (!this._typeToOid.has(typeName)) this._typeToOid.set(typeName, oid);
      }
    }
  }

  /**
   * Table metadata for a named table-entry OBJECT-TYPE (e.g. 'ifEntry'):
   * { name, oid, typeName, index: ['ifIndex', ...], access }.
   * Returns null when the object is not a table entry (no INDEX clause).
   */
  tableInfo(objectName) {
    const def = this.define(objectName);
    if (!def || !def['OBJECT-TYPE'] || !def['OBJECT-TYPE'].INDEX) return null;
    const ot = def['OBJECT-TYPE'];
    const syn = ot.SYNTAX;
    return {
      name: objectName,
      oid: this.oidOf(objectName),
      typeName: Array.isArray(syn) ? syn[0] : syn,
      index: Array.isArray(ot.INDEX) ? ot.INDEX.slice() : [ot.INDEX],
      access: ot.ACCESS,
    };
  }

  /**
   * ACCESS of a table column's OBJECT-TYPE (e.g. column 'ifAdminStatus'
   * of entry 'ifEntry'). Falls back to the entry's own ACCESS when the
   * column has no OBJECT-TYPE of its own, then to 'read-only'.
   */
  columnAccess(objectName, columnName) {
    const cdef = this.define(columnName);
    if (cdef && cdef['OBJECT-TYPE'] && cdef['OBJECT-TYPE'].ACCESS) {
      return cdef['OBJECT-TYPE'].ACCESS;
    }
    const edef = this.define(objectName);
    if (edef && edef['OBJECT-TYPE'] && edef['OBJECT-TYPE'].ACCESS) {
      return edef['OBJECT-TYPE'].ACCESS;
    }
    return 'read-only';
  }

  /** All OBJECT-TYPE names in load order. */
  objectNames() {
    return [...this.defs.keys()].filter(n => { const d = this.define(n); return d && d['OBJECT-TYPE']; });
  }
}

module.exports = { MibRegistry };
