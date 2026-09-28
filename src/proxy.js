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
  constructor(registry, objectName, link) {
    super();
    const info = registry.objectInfo(objectName);
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
// Public API
// ---------------------------------------------------------------------------

/**
 * Marshal a named MIB object into a live proxy on the link.
 * Tables (INDEX clause) -> TableProxy; anything else -> ValueProxy.
 */
function marshal(registry, objectName, link) {
  if (!link || typeof link.send !== 'function' || typeof link.onMessage !== 'function') {
    throw new TypeError('marshal needs a link { send(msg), onMessage(cb) } — see linkFromStreams()');
  }
  return registry.tableInfo(objectName)
    ? new TableProxy(registry, objectName, link)
    : new ValueProxy(registry, objectName, link);
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
};
