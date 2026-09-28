'use strict';
/**
 * proxy — live remote objects over OID-tagged frames.
 *
 *   marshal(registry, objectName, link) -> proxy
 *   unmarshal(proxy)                   -> plain snapshot
 *   linkFromStreams(encoder, decoder)  -> link
 *
 * Getters subscribe, setters publish — the jsix accessor pattern, backed by
 * the asnstream frame stream:
 *   - reading a property returns the last-known value (undefined until the
 *     first frame for its OID arrives); constructing the proxy subscribes it.
 *   - writing a property encodes the value and publishes an OID-tagged frame.
 *
 * ACCESS is enforced at the language level: writing a read-only object or
 * column throws. OBJECT-TYPEs with an INDEX clause marshal to live table
 * collections keyed by index; rows materialize as frames arrive, and row
 * column setters publish full-row updates (read-modify-write on the cached
 * row — you cannot set a column of a row you have never seen, mirroring
 * SNMP's row-existence semantics).
 *
 * Proxies are EventEmitters:
 *   ValueProxy  'update' (value)
 *   RowProxy    'update' (row)
 *   TableProxy  'row' (rowProxy) on first sight, 'update' (key, rowProxy)
 * plus jsix-accessor-compatible 'get' (oid[, column]) / 'set' (oid, value).
 *
 * A link is { send(msg), onMessage(cb) -> unsub } where msg is the
 * MessageEncoder input shape { oid?, type?, value } and cb receives the
 * MessageDecoder output shape { oid, type, value } / { oid, type: null, raw }.
 * Subscription is implicit and local: one dispatcher per link routes each
 * incoming frame to the proxies whose OID matches. (Server-side filtering
 * is a later optimization; the wire already carries everything.)
 *
 * Beyond SMI: marshal() also accepts any named ASN.1 type, not just
 * OBJECT-TYPEs. A SEQUENCE becomes a StructProxy (fields as live
 * properties, whole-struct publish), a SEQUENCE OF / SET OF becomes a
 * ListProxy (ordinal-keyed live collection), and any other type becomes a
 * ValueProxy. Schema types default to read-write ACCESS (override with
 * marshal's { access } option) and need a wire OID — see
 * registry.setTypeOid / autoAssignOids.
 */
const { EventEmitter } = require('events');

const READABLE = new Set(['read-only', 'read-write', 'read-create']);
const WRITABLE = new Set(['read-write', 'read-create']);

function assertReadable(access, what) {
  if (!READABLE.has(access)) throw new Error(`${what} is not readable (ACCESS ${access})`);
}
function assertWritable(access, what) {
  if (!WRITABLE.has(access)) throw new Error(`${what} is not writable (ACCESS ${access})`);
}

function deepClone(v) {
  if (Buffer.isBuffer(v)) return Buffer.from(v);
  if (Array.isArray(v)) return v.map(deepClone);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v)) o[k] = deepClone(v[k]);
    return o;
  }
  return v;
}

// ---------------------------------------------------------------------------
// Link hub: one frame dispatcher per link, shared by all proxies on it.
// ---------------------------------------------------------------------------
const hubs = new WeakMap(); // link -> Map<oid, Set<fn>>

function hubFor(link) {
  let hub = hubs.get(link);
  if (!hub) {
    hub = new Map();
    const routes = hub;
    link.onMessage((msg) => {
      if (!msg || typeof msg.oid !== 'string') return;
      const set = routes.get(msg.oid);
      if (set) for (const fn of Array.from(set)) fn(msg);
    });
    hubs.set(link, hub);
  }
  return hub;
}

function hubAdd(link, oid, fn) {
  const hub = hubFor(link);
  let set = hub.get(oid);
  if (!set) { set = new Set(); hub.set(oid, set); }
  set.add(fn);
}

function hubRemove(link, oid, fn) {
  const hub = hubs.get(link);
  if (!hub) return;
  const set = hub.get(oid);
  if (set) {
    set.delete(fn);
    if (set.size === 0) hub.delete(oid);
  }
}

/** Adapt a { encoder, decoder } pair (tcp/ws connection) into a link. */
function linkFromStreams(encoder, decoder) {
  return {
    send(msg) { encoder.write(msg); },
    onMessage(cb) { decoder.on('data', cb); return () => decoder.off('data', cb); },
  };
}

// ---------------------------------------------------------------------------
// ValueProxy — a single scalar / non-table object (e.g. 'sysContact').
// ---------------------------------------------------------------------------
class ValueProxy extends EventEmitter {
  constructor(registry, objectName, link, opts = {}) {
    super();
    // opts.spec lets marshal() reuse this class for non-MIB scalar types:
    // { name, oid, typeName, access }.
    const info = opts.spec || registry.objectInfo(objectName);
    this._registry = registry;
    this._link = link;
    this._name = objectName;
    this._oid = info.oid;
    this._typeName = registry.typeOfOid(info.oid);
    this._access = info.access || 'read-only';
    this._value = undefined;
    this._onFrame = (msg) => {
      if (msg.type === null || msg.type === undefined) return;
      this._value = msg.value;
      this.emit('update', this._value);
    };
    hubAdd(link, this._oid, this._onFrame);
  }

  /** Getter: subscribes at construction; returns the last-known value. */
  get value() {
    assertReadable(this._access, this._name);
    this.emit('get', this._oid);
    return this._value;
  }

  /** Setter: publishes an OID-tagged frame. Throws on read-only objects. */
  set value(v) {
    assertWritable(this._access, this._name);
    this._link.send({ oid: this._oid, type: this._typeName, value: v });
    this._value = v;
    this.emit('update', v);
    this.emit('set', this._oid, v);
  }

  /** Detach from the link; the proxy keeps its last-known value. */
  release() {
    hubRemove(this._link, this._oid, this._onFrame);
    this.removeAllListeners();
  }
}

// ---------------------------------------------------------------------------
// RowProxy — one materialized table row; columns are live properties.
// ---------------------------------------------------------------------------
class RowProxy extends EventEmitter {
  constructor(table, key) {
    super();
    this._table = table;
    this._key = key;
    this._row = null; // last-known full row, or null until first frame
    for (const f of table._fields) {
      Object.defineProperty(this, f.name, {
        enumerable: true,
        configurable: true,
        get: () => {
          this.emit('get', this._table._oid, f.name);
          return this._row ? this._row[f.name] : undefined;
        },
        set: (v) => this._setColumn(f.name, v),
      });
    }
  }

  _setColumn(col, v) {
    const access = this._table._registry.columnAccess(this._table._name, col);
    assertWritable(access, `${this._table._name}.${col}[${this._key}]`);
    if (!this._row) {
      throw new Error(`Cannot set ${col}: row ${this._key} of ${this._table._name} not present`);
    }
    this._table.publish(Object.assign({}, this._row, { [col]: v }));
  }

  _applyRow(row) {
    this._row = row;
    this.emit('update', row);
  }
}

// ---------------------------------------------------------------------------
// TableProxy — a live collection of RowProxies keyed by INDEX.
// ---------------------------------------------------------------------------
class TableProxy extends EventEmitter {
  constructor(registry, objectName, link) {
    super();
    const tinfo = registry.tableInfo(objectName);
    if (!tinfo) throw new Error(`${objectName} is not a table (no INDEX clause)`);
    this._registry = registry;
    this._link = link;
    this._name = objectName;
    this._oid = tinfo.oid;
    this._typeName = tinfo.typeName;
    this._index = tinfo.index;
    const desc = registry.resolveType(tinfo.typeName);
    if (!desc.fields) throw new Error(`Table entry ${tinfo.typeName} is not a SEQUENCE`);
    this._fields = desc.fields;
    this._rows = new Map(); // instance key -> RowProxy
    this._onFrame = (msg) => {
      if (msg.type === null || msg.type === undefined) return;
      this._ingest(msg.value);
    };
    hubAdd(link, this._oid, this._onFrame);
  }

  _instanceKey(row) {
    return this._index.map((c) => {
      if (row[c] === undefined) throw new Error(`Row for ${this._name} missing index column ${c}`);
      return String(row[c]);
    }).join('.');
  }

  _ingest(row) {
    const key = this._instanceKey(row);
    let rp = this._rows.get(key);
    const isNew = !rp;
    if (isNew) {
      rp = new RowProxy(this, key);
      this._rows.set(key, rp);
    }
    rp._applyRow(row);
    // 'row' fires after the data is applied, so handlers see a populated proxy.
    if (isNew) this.emit('row', rp);
    this.emit('update', key, rp);
    return rp;
  }

  /**
   * Publish a full row: announces it on the stream and applies it locally.
   * This is the agent side of the table (e.g. a poll loop), and also what
   * row column setters call after read-modify-write.
   */
  publish(row) {
    this._link.send({ oid: this._oid, type: this._typeName, value: row });
    return this._ingest(row);
  }

  /**
   * Live row proxy for an index key. Created on demand — like jsix's
   * delayed remote getter, it fills in as frames arrive.
   */
  get(key) {
    const k = String(key);
    let rp = this._rows.get(k);
    if (!rp) { rp = new RowProxy(this, k); this._rows.set(k, rp); }
    return rp;
  }

  /** True when we hold row data for the key (not just a placeholder). */
  has(key) {
    const rp = this._rows.get(String(key));
    return !!rp && rp._row !== null;
  }

  keys() { return [...this._rows.keys()]; }
  get size() { return this._rows.size; }

  release() {
    hubRemove(this._link, this._oid, this._onFrame);
    // Rows are kept as last-known state (like ValueProxy keeps its value);
    // the table is simply frozen at detach time.
  }
}

// ---------------------------------------------------------------------------
// StructProxy — a live SEQUENCE value: fields are live properties, setting
// one publishes the whole struct (read-modify-write on the cached value).
// The schema-type analogue of RowProxy, without a table around it.
// ---------------------------------------------------------------------------
class StructProxy extends EventEmitter {
  constructor(registry, typeName, link, opts = {}) {
    super();
    const desc = registry.resolveType(typeName);
    if (desc.kind !== 'sequence') throw new Error(`${typeName} is not a SEQUENCE`);
    this._registry = registry;
    this._link = link;
    this._name = typeName;
    this._typeName = typeName;
    this._oid = opts.oid || registry.oidOfType(typeName);
    this._access = opts.access || 'read-write';
    this._struct = null; // last-known value, or null until the first frame
    this._fields = desc.fields;
    for (const f of this._fields) {
      Object.defineProperty(this, f.name, {
        enumerable: true,
        configurable: true,
        get: () => {
          this.emit('get', this._oid, f.name);
          return this._struct ? this._struct[f.name] : undefined;
        },
        set: (v) => this._setField(f.name, v),
      });
    }
    this._onFrame = (msg) => {
      if (msg.type === null || msg.type === undefined) return;
      this._applyStruct(msg.value);
    };
    hubAdd(link, this._oid, this._onFrame);
  }

  _setField(name, v) {
    assertWritable(this._access, `${this._name}.${name}`);
    if (!this._struct) throw new Error(`Cannot set ${name}: no ${this._name} seen yet`);
    this.publish(Object.assign({}, this._struct, { [name]: v }));
    this.emit('set', this._oid, this._struct);
  }

  /**
   * Publish a whole struct: announces it on the stream and applies it
   * locally. The agent side of the struct, and what field setters call
   * after read-modify-write.
   */
  publish(obj) {
    assertWritable(this._access, this._name);
    this._link.send({ oid: this._oid, type: this._typeName, value: obj });
    this._applyStruct(obj);
    return this;
  }

  _applyStruct(obj) {
    this._struct = obj;
    this.emit('update', obj);
  }

  /** Detach from the link; the proxy keeps its last-known struct. */
  release() {
    hubRemove(this._link, this._oid, this._onFrame);
    this.removeAllListeners();
  }
}

// ---------------------------------------------------------------------------
// ElementProxy — one element of a ListProxy whose element type is a
// SEQUENCE; fields are live properties bound to that ordinal position.
// ---------------------------------------------------------------------------
class ElementProxy extends EventEmitter {
  constructor(list, index) {
    super();
    this._list = list;
    this._index = index;
    this._el = null;
    for (const f of list._elDesc.fields) {
      Object.defineProperty(this, f.name, {
        enumerable: true,
        configurable: true,
        get: () => {
          this.emit('get', list._oid, `${index}.${f.name}`);
          return this._el ? this._el[f.name] : undefined;
        },
        set: (v) => {
          assertWritable(list._access, `${list._name}[${index}].${f.name}`);
          if (!this._el) throw new Error(`Cannot set ${f.name}: element ${index} not present`);
          list.set(index, Object.assign({}, this._el, { [f.name]: v }));
        },
      });
    }
  }

  _applyElement(el) {
    this._el = el === undefined ? null : el;
    this.emit('update', this._el);
  }
}

// ---------------------------------------------------------------------------
// ListProxy — a live SEQUENCE OF / SET OF collection, ordinal-keyed.
// Scalar elements are read with get(i); SEQUENCE elements get live
// ElementProxies. publish() is the agent side; set/push do
// read-modify-write publishes.
// ---------------------------------------------------------------------------
class ListProxy extends EventEmitter {
  constructor(registry, typeName, link, opts = {}) {
    super();
    const desc = registry.resolveType(typeName);
    if (desc.kind !== 'sequenceOf' && desc.kind !== 'setOf') {
      throw new Error(`${typeName} is not a SEQUENCE OF / SET OF`);
    }
    this._registry = registry;
    this._link = link;
    this._name = typeName;
    this._typeName = typeName;
    this._oid = opts.oid || registry.oidOfType(typeName);
    this._access = opts.access || 'read-write';
    this._elDesc = registry.resolveType(desc.elementRef);
    this._items = null; // last-known array, or null until the first frame
    this._elements = new Map(); // index -> ElementProxy, for SEQUENCE elements
    this._onFrame = (msg) => {
      if (msg.type === null || msg.type === undefined) return;
      this._applyItems(msg.value);
    };
    hubAdd(link, this._oid, this._onFrame);
  }

  get length() { return this._items ? this._items.length : 0; }

  /** Last-known array (detached clone), or [] before the first frame. */
  values() { return this._items ? deepClone(this._items) : []; }

  /**
   * Publish a whole array: announces it on the stream and applies it
   * locally. The agent side of the collection.
   */
  publish(array) {
    assertWritable(this._access, this._name);
    if (!Array.isArray(array)) throw new TypeError(`Expected array for ${this._name}`);
    this._link.send({ oid: this._oid, type: this._typeName, value: array });
    this._applyItems(array);
    return this;
  }

  _applyItems(array) {
    this._items = array;
    for (const [i, ep] of this._elements) ep._applyElement(array[i]);
    this.emit('update', this.values());
  }

  /**
   * Live element at ordinal i. For SEQUENCE element types this is an
   * ElementProxy with live fields (created on demand, fills in as frames
   * arrive); for scalar elements it's the last-known value.
   */
  get(i) {
    if (this._elDesc.kind === 'sequence') {
      let ep = this._elements.get(i);
      if (!ep) {
        ep = new ElementProxy(this, i);
        this._elements.set(i, ep);
        // Seed from the last-known array when we already hold it.
        ep._applyElement(this._items ? this._items[i] : undefined);
      }
      return ep;
    }
    this.emit('get', this._oid, i);
    return this._items ? this._items[i] : undefined;
  }

  /** Replace element i (read-modify-write publish). */
  set(i, v) {
    assertWritable(this._access, `${this._name}[${i}]`);
    if (!this._items) throw new Error(`Cannot set [${i}]: no ${this._name} seen yet`);
    const next = this._items.slice();
    next[i] = v;
    this.publish(next);
    this.emit('set', this._oid, next);
  }

  /** Append an element (read-modify-write publish). */
  push(v) {
    this.publish(this.values().concat([v]));
    this.emit('set', this._oid, this.values());
  }

  /** Detach from the link; the proxy keeps its last-known array. */
  release() {
    hubRemove(this._link, this._oid, this._onFrame);
    this.removeAllListeners();
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Marshal a named object into a live proxy on the link.
 *
 * MIB OBJECT-TYPEs keep their existing behavior: tables (INDEX clause) ->
 * TableProxy, anything else -> ValueProxy with SMI ACCESS enforcement.
 *
 * Any other named ASN.1 type also marshals: SEQUENCE -> StructProxy,
 * SEQUENCE OF / SET OF -> ListProxy, anything else -> ValueProxy.
 * Schema types default to read-write (override with { access }) and need a
 * wire OID — assign one with registry.setTypeOid() / autoAssignOids().
 */
function marshal(registry, name, link, opts = {}) {
  if (!link || typeof link.send !== 'function' || typeof link.onMessage !== 'function') {
    throw new TypeError('marshal needs a link { send(msg), onMessage(cb) } — see linkFromStreams()');
  }
  if (registry.tableInfo(name)) return new TableProxy(registry, name, link);
  const def = typeof registry.define === 'function' ? registry.define(name) : undefined;
  if (def && def['OBJECT-TYPE']) return new ValueProxy(registry, name, link);
  const desc = registry.resolveType(name);
  const access = opts.access || 'read-write';
  let oid;
  try {
    oid = registry.oidOfType(name);
  } catch {
    throw new Error(
      `${name} has no OID on the wire — assign one with ` +
      `registry.setTypeOid('${name}', '1.3.6.1.4.1.<pen>.<n>') or registry.autoAssignOids(base)`
    );
  }
  if (desc.kind === 'sequence') return new StructProxy(registry, name, link, { oid, access });
  if (desc.kind === 'sequenceOf' || desc.kind === 'setOf') {
    return new ListProxy(registry, name, link, { oid, access });
  }
  return new ValueProxy(registry, name, link, { spec: { name, oid, typeName: name, access } });
}

/**
 * Snapshot a proxy into plain data, detached from the stream —
 * the unmarshal half of the jsix accessor vocabulary.
 */
function unmarshal(proxy) {
  if (proxy instanceof TableProxy) {
    const out = {};
    for (const [k, rp] of proxy._rows) out[k] = rp._row ? deepClone(rp._row) : null;
    return out;
  }
  if (proxy instanceof RowProxy) return proxy._row ? deepClone(proxy._row) : null;
  if (proxy instanceof StructProxy) return proxy._struct ? deepClone(proxy._struct) : null;
  if (proxy instanceof ElementProxy) return proxy._el ? deepClone(proxy._el) : null;
  if (proxy instanceof ListProxy) return proxy._items ? deepClone(proxy._items) : [];
  if (proxy instanceof ValueProxy) return deepClone(proxy._value);
  throw new TypeError('unmarshal needs a proxy from marshal()');
}

module.exports = {
  marshal,
  unmarshal,
  linkFromStreams,
  ValueProxy,
  RowProxy,
  TableProxy,
  StructProxy,
  ElementProxy,
  ListProxy,
};
