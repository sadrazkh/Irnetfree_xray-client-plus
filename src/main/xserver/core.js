'use strict';
/**
 * plus: the Server tab's runtime. One ServerCore owns one child process —
 * the local Xray server — apart from the client tunnel xrayManager runs. It
 * starts and stops that core, reads its /debug/vars every few seconds to
 * meter each client, disables clients that ran out of quota or time, and
 * brings the core back when it dies. Everything that touches the machine or
 * the clock (spawn, timers, the metrics GET, the free port) is injected, so
 * the tests drive it with fakes and never bind a socket.
 *
 * /debug/vars, as both cores in bin/ nest it (read from a live core):
 *   stats.inbound.<tag>.{uplink,downlink}
 *   stats.user.<email>.{uplink,downlink}
 * beside the stats.outbound block the client meter already reads. The
 * counters start at zero with every core start, so the meter keeps the last
 * reading and adds the deltas to each client's lifetime `used`.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn: nodeSpawn } = require('child_process');
const { engineRunArgs } = require('../engines');
const { getFreePort: nodeGetFreePort } = require('../xrayManager');
const { normalizeModel, validateModel, buildServerConfig } = require('./config');

const POLL_MS = 300;            // how often the metrics port is asked while starting
const POLL_TRIES = 20;          // 6 s in all before a silent core is given up on
const TICK_MS = 5000;
const RESTART_DEBOUNCE_MS = 10000;
const CRASH_BACKOFF_MS = [2000, 5000, 15000];
const STABLE_MS = 60000;        // a core up this long has survived its incident
const STOP_WAIT_MS = 3000;
const RING = 300;
const RECENT_BYTES = 4000;      // enough output to find the reason for an exit in

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/** The per-inbound and per-user counters out of a parsed /debug/vars body. Never throws. */
function parseServerVars(vars) {
  const st = vars && vars.stats && typeof vars.stats === 'object' ? vars.stats : {};
  const read = (block) => {
    const out = {};
    if (!block || typeof block !== 'object') return out;
    for (const key of Object.keys(block)) {
      const c = block[key] || {};
      out[key] = { up: num(c.uplink), down: num(c.downlink) };
    }
    return out;
  };
  return { inbounds: read(st.inbound), users: read(st.user) };
}

/**
 * The netsh arguments the firewall button runs, and nothing else here runs
 * them: index.js does, on Windows, when the user presses the button.
 */
function firewallArgs(name, port, allow) {
  return allow
    ? ['advfirewall', 'firewall', 'add', 'rule', 'name=' + name, 'dir=in', 'action=allow', 'protocol=TCP', 'localport=' + port]
    : ['advfirewall', 'firewall', 'delete', 'rule', 'name=' + name];
}

/** One GET of /debug/vars; null when the port does not answer or the body is not JSON. */
function queryVarsHttp(apiPort) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: apiPort, path: '/debug/vars', timeout: 3000 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

/** Whole lines out of a stream, however the chunks fall. */
function lineReader(stream, onLine) {
  if (!stream || typeof stream.on !== 'function') return;
  let buf = '';
  stream.on('data', (d) => {
    buf += d.toString('utf8');
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, '').trim();
      buf = buf.slice(i + 1);
      if (line) onLine(line);
    }
  });
  stream.on('end', () => { const line = buf.trim(); buf = ''; if (line) onLine(line); });
  stream.on('error', () => { /* a closed pipe is the exit's business */ });
}

/** xray marks its lines; a bare "Failed to start" or a panic is an error too. */
function levelOf(line) {
  if (/\[Error\]/.test(line) || /^(Failed|panic)/i.test(line)) return 'error';
  if (/\[Warning\]/.test(line)) return 'warn';
  return 'info';
}

/**
 * The reason in the core's own words: the deepest " > " segment of the last
 * line that says something failed (the same reading xrayManager gives the
 * client core), else the plain exit code.
 */
function exitReason(recent, code, signal) {
  if (recent) {
    const lines = recent.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const fail = lines.reverse().find(l => /failed|error|panic|invalid|unknown|cannot|no such/i.test(l));
    if (fail) {
      const parts = fail.split(' > ');
      const msg = parts[parts.length - 1].trim().replace(/^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?\s*/, '');
      if (msg) return msg;
    }
  }
  return `the core exited (code ${code === null || code === undefined ? (signal || '-') : code})`;
}

class ServerCore {
  constructor(opts) {
    const o = opts || {};
    this.dataDir = o.dataDir;
    this.xray = o.xray;
    this.getModel = o.getModel || (() => ({}));
    this.setModel = o.setModel || (() => {});
    this.send = o.send || (() => {});
    this.log = o.log || (() => {});
    this.notify = o.notify || (() => {});
    this.getServers = o.getServers || (() => []);
    this.geoAvailable = o.geoAvailable;
    this.spawn = o.spawn || nodeSpawn;
    this.now = o.now || Date.now;
    this.setTimeoutFn = o.setTimeout || setTimeout;
    this.clearTimeoutFn = o.clearTimeout || clearTimeout;
    this.queryVars = o.queryVars || queryVarsHttp;
    this.getFreePort = o.getFreePort || nodeGetFreePort;
    this.platform = o.platform || process.platform;

    this.state = 'stopped';
    this.proc = null;
    this.since = 0;
    this.engine = '';
    this.apiPort = 0;
    this.error = '';
    this.ring = [];
    this.recent = '';
    this.last = {};               // email -> the previous /debug/vars reading
    this.online = new Set();      // emails whose counter moved in the last tick
    this.tickTimer = null;
    this.restartTimer = null;     // the debounced restart after an enforcer change
    this.crashTimer = null;       // the back-off restart after an unexpected exit
    this.crashes = 0;
    this.stopping = false;        // the exit in flight was asked for
    this.gen = 0;                 // bumped by stop(): a start() past its awaits must notice
    this.sleepers = new Set();
    this.startP = null;
    this.ticking = false;
  }

  /* ----------------------------- state ----------------------------- */

  _model() { return normalizeModel(this.getModel()); }

  _geo() { return typeof this.geoAvailable === 'function' ? !!this.geoAvailable() : this.geoAvailable !== false; }

  _setState(state, error) {
    this.state = state;
    this.error = error || '';
    this._emitStatus();
  }

  _emitStatus() {
    try { this.send('xserver-status', this.status()); } catch { /* window gone */ }
  }

  _fail(msg, extra) {
    this._setState('error', msg);
    this.log('Server core: ' + msg, 'error');
    return Object.assign({ ok: false, error: msg }, extra || {});
  }

  status() {
    const model = this._model();
    const inbounds = model.inbounds.map((i) => {
      let up = 0, down = 0;
      const clients = i.clients.map((c) => {
        up += c.used.up;
        down += c.used.down;
        return { id: c.id, email: c.email, enabled: c.enabled, disabledBy: c.disabledBy, up: c.used.up, down: c.used.down, online: this.online.has(c.email) };
      });
      return { id: i.id, tag: i.tag, port: i.port, enabled: i.enabled, up, down, clients };
    });
    return {
      state: this.state,
      pid: this.proc ? (this.proc.pid || null) : null,
      since: this.since,
      engine: this.engine,
      apiPort: this.apiPort,
      error: this.error,
      inbounds
    };
  }

  logLines() { return this.ring.slice(); }

  /* ----------------------------- timers ----------------------------- */

  _sleep(ms) {
    return new Promise((resolve) => {
      const s = { h: null, resolve };
      s.h = this.setTimeoutFn(() => { this.sleepers.delete(s); resolve(); }, ms);
      this.sleepers.add(s);
    });
  }

  /** An exit or a stop ends every wait at once; the waiter re-checks the state. */
  _wakeAll() {
    for (const s of this.sleepers) { this.clearTimeoutFn(s.h); s.resolve(); }
    this.sleepers.clear();
  }

  _clearTick() {
    if (this.tickTimer) { this.clearTimeoutFn(this.tickTimer); this.tickTimer = null; }
  }

  _armTick() {
    this._clearTick();
    this.tickTimer = this.setTimeoutFn(() => { this.tickTimer = null; this._tick(); }, TICK_MS);
  }

  _cancelRestarts() {
    if (this.restartTimer) { this.clearTimeoutFn(this.restartTimer); this.restartTimer = null; }
    if (this.crashTimer) { this.clearTimeoutFn(this.crashTimer); this.crashTimer = null; }
  }

  /* ----------------------------- start ----------------------------- */

  /** `{ ok }` or `{ ok:false, error }`; the state says the same. Never throws. */
  start(opts) {
    if (this.proc) return Promise.resolve({ ok: true, already: true });
    if (this.startP) return this.startP;
    this.startP = this._start(opts || {}).catch((e) => this._fail('start failed: ' + ((e && e.message) || String(e)))).finally(() => { this.startP = null; });
    return this.startP;
  }

  async _start(opts) {
    this._cancelRestarts();
    if (!opts.auto) this.crashes = 0;      // a start the user asked for begins with a clean slate
    this.stopping = false;
    const gen = ++this.gen;
    const bailed = () => ({ ok: false, error: this.state === 'stopped' ? 'stopped' : (this.error || 'the core exited on startup') });

    const model = this._model();
    this.engine = model.engine;
    const v = validateModel(model, { servers: this.getServers() });
    if (!v.ok) {
      const e = v.errors[0];
      return this._fail(`${e.path}: ${e.msg}`, { errors: v.errors });
    }
    // A client that ran out while the core was down leaves the config now,
    // not five seconds and a restart later.
    if (this._enforce(model).changed) this.setModel(model);

    let apiPort;
    try { apiPort = await this.getFreePort(); } catch (e) { return this._fail('no free port for the metrics listener: ' + e.message); }
    if (gen !== this.gen) return bailed();
    const config = buildServerConfig(model, { apiPort, servers: this.getServers(), geoAvailable: this._geo() });
    const t = await this.xray.validate(config, model.engine);
    if (gen !== this.gen) return bailed();
    if (!t || !t.ok) return this._fail((t && t.error) || 'the core refused the config');

    const { id, bin } = this.xray.resolveEngine(model.engine, { quiet: true });
    if (!bin) return this._fail('core binary not found');
    this.engine = id;

    let cfgPath;
    try {
      const dir = path.join(this.dataDir, 'xserver');
      fs.mkdirSync(dir, { recursive: true });
      cfgPath = path.join(dir, 'config.json');
      fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2), 'utf8');
    } catch (e) { return this._fail('cannot write the config: ' + e.message); }

    let proc;
    try {
      proc = this.spawn(bin, engineRunArgs(id, cfgPath), { cwd: path.dirname(bin), windowsHide: true, env: this.xray.spawnEnv() });
    } catch (e) { return this._fail('spawn failed: ' + e.message); }
    this._attach(proc);
    this.proc = proc;
    this.apiPort = apiPort;
    this.recent = '';
    this.last = {};
    this.online = new Set();
    this._setState('starting', '');
    this.log(`Server core: starting ${path.basename(bin)} (metrics on 127.0.0.1:${apiPort})`, 'info');

    // The core is up when its metrics port answers; an exit before that is
    // the startup failure, reported in the core's own words.
    for (let i = 0; i < POLL_TRIES; i++) {
      if (this.proc !== proc) return bailed();
      const vars = await this.queryVars(apiPort);
      if (this.proc !== proc) return bailed();
      if (vars) {
        this.since = this.now();
        this._setState('running', '');
        this._armTick();
        this.log(`Server core: running (pid ${proc.pid})`, 'info');
        return { ok: true };
      }
      await this._sleep(POLL_MS);
    }
    if (this.proc !== proc) return bailed();
    this.stopping = true;
    this._kill(proc);
    await this._waitExit(proc, STOP_WAIT_MS);
    if (this.proc === proc) { this.proc = null; }
    return this._fail('the core did not answer on its metrics port');
  }

  _attach(proc) {
    // A child that cannot be started emits 'error' — with no listener Node
    // re-throws it as an uncaught exception. 'exit' may not follow, so this
    // is terminal on its own.
    proc.on('error', (err) => {
      if (this.proc !== proc) return;
      this.proc = null;
      this._clearTick();
      this._fail('spawn error: ' + err.message);
      this._wakeAll();
    });
    lineReader(proc.stdout, (line) => this._onLine(line));
    lineReader(proc.stderr, (line) => this._onLine(line));
    proc.on('exit', (code, signal) => this._onExit(proc, code, signal));
  }

  _onLine(line) {
    this.ring.push(line);
    if (this.ring.length > RING) this.ring.splice(0, this.ring.length - RING);
    this.recent = (this.recent + line + '\n').slice(-RECENT_BYTES);
    try { this.send('xserver-log', { line, level: levelOf(line) }); } catch { /* window gone */ }
  }

  _onExit(proc, code, signal) {
    if (this.proc !== proc) return;         // a child stop() already gave up on
    this.proc = null;
    this._clearTick();
    this.online = new Set();
    this.last = {};
    const was = this.state;
    const asked = this.stopping;
    const reason = exitReason(this.recent, code, signal);
    this.log(`Server core: exited (code=${code} signal=${signal || '-'})`, asked ? 'info' : 'error');
    this._wakeAll();
    if (asked) { this._setState('stopped', ''); return; }
    if (was !== 'running') {
      // a startup exit: start() returns it, the log keeps the reason
      this.log('Server core: ' + reason, 'error');
      this._setState('error', reason);
      return;
    }

    // Unexpected, while running: bring it back, slower each time, then give up.
    this.crashes++;
    if (this.crashes === 1) {
      try { this.notify('IRNetFree Plus', 'The server core exited unexpectedly — restarting it.'); } catch { /* headless without a notifier */ }
    }
    if (this.crashes > CRASH_BACKOFF_MS.length) {
      this.crashes = 0;
      this._setState('error', 'the core keeps exiting: ' + reason);
      this.log('Server core: keeps exiting, giving up: ' + reason, 'error');
      return;
    }
    const wait = CRASH_BACKOFF_MS[this.crashes - 1];
    this._setState('error', `${reason} — restarting in ${wait / 1000} s`);
    this.log(`Server core: restarting in ${wait / 1000} s (${this.crashes}/${CRASH_BACKOFF_MS.length})`, 'warn');
    this.crashTimer = this.setTimeoutFn(() => { this.crashTimer = null; this.start({ auto: true }); }, wait);
  }

  /* ----------------------------- stop ----------------------------- */

  _kill(proc) {
    try { proc.kill(); } catch { /* already gone */ }
    if (this.platform === 'win32' && proc.pid) {
      // kill() alone leaves a console child behind on Windows; the tree kill is what ends it
      try {
        const t = this.spawn('taskkill', ['/pid', String(proc.pid), '/t', '/f'], { windowsHide: true });
        if (t && typeof t.on === 'function') t.on('error', () => { /* no taskkill: the kill() above has to do */ });
      } catch { /* same */ }
    }
  }

  /** True when the child exited within `ms`. */
  _waitExit(proc, ms) {
    return new Promise((resolve) => {
      if (this.proc !== proc) return resolve(true);
      let done = false;
      const h = this.setTimeoutFn(() => { if (!done) { done = true; resolve(false); } }, ms);
      proc.once('exit', () => { if (!done) { done = true; this.clearTimeoutFn(h); resolve(true); } });
    });
  }

  async stop() {
    this._cancelRestarts();
    this.crashes = 0;
    this.gen++;
    const proc = this.proc;
    if (!proc) {
      this._wakeAll();
      if (this.state !== 'stopped') this._setState('stopped', '');
      this.since = 0;
      return this.status();
    }
    this.stopping = true;
    this.log('Server core: stopping', 'info');
    this._kill(proc);
    const exited = await this._waitExit(proc, STOP_WAIT_MS);
    if (!exited && this.proc === proc) {
      // It will die when the OS gets to it; nothing more to wait for here.
      this.proc = null;
      this._clearTick();
      this.log('Server core: did not exit in 3 s, detached', 'warn');
    }
    this.since = 0;
    this.online = new Set();
    this.last = {};
    this._setState('stopped', '');
    return this.status();
  }

  async restart() {
    await this.stop();
    return this.start();
  }

  /* ----------------------------- the tick ----------------------------- */

  async _tick() {
    if (this.state !== 'running' || this.ticking) return;
    this.ticking = true;
    const proc = this.proc;
    try {
      const vars = await this.queryVars(this.apiPort);
      if (this.state !== 'running' || this.proc !== proc) return;
      if (vars) {
        const parsed = parseServerVars(vars);
        const model = this._model();
        const online = new Set();
        let moved = false;
        for (const i of model.inbounds) {
          for (const c of i.clients) {
            const cur = parsed.users[c.email];
            if (!cur) continue;
            const prev = this.last[c.email] || { up: 0, down: 0 };
            const dUp = Math.max(0, cur.up - prev.up);
            const dDown = Math.max(0, cur.down - prev.down);
            if (dUp || dDown) {
              c.used.up += dUp;
              c.used.down += dDown;
              online.add(c.email);
              moved = true;
            }
          }
        }
        this.last = parsed.users;
        this.online = online;
        const e = this._enforce(model);
        if (moved || e.changed) this.setModel(model);
        if (e.membership) this._scheduleRestart();
      }
      if (this.now() - this.since >= STABLE_MS) this.crashes = 0;
      this._emitStatus();
    } catch (err) {
      this.log('Server core: tick failed: ' + ((err && err.message) || String(err)), 'warn');
    } finally {
      this.ticking = false;
      if (this.state === 'running' && this.proc === proc) this._armTick();
    }
  }

  /**
   * Quota and expiry, both ways: a client that ran out is disabled with the
   * reason, a client the enforcer disabled is enabled again once the reason
   * no longer holds. A client the user disabled (no reason) is left alone.
   * Returns { changed, membership }: membership means the config's client
   * list is different now and the core has to be restarted for it.
   */
  _enforce(model) {
    const now = this.now();
    let changed = false, membership = false;
    for (const i of model.inbounds) {
      for (const c of i.clients) {
        const expired = c.expiresAt > 0 && c.expiresAt < now;
        const over = c.quotaBytes > 0 && c.used.up + c.used.down >= c.quotaBytes;
        const reason = expired ? 'expired' : (over ? 'quota' : '');
        if (reason && c.enabled) {
          c.enabled = false;
          c.disabledBy = reason;
          changed = membership = true;
          this.log(`Server: client "${c.email}" disabled (${reason})`, 'warn');
        } else if (reason && c.disabledBy && c.disabledBy !== reason) {
          c.disabledBy = reason;          // still out, for a different reason now
          changed = true;
        } else if (!reason && !c.enabled && c.disabledBy) {
          c.enabled = true;
          c.disabledBy = '';
          changed = membership = true;
          this.log(`Server: client "${c.email}" enabled again`, 'info');
        }
      }
    }
    return { changed, membership };
  }

  _scheduleRestart() {
    if (this.restartTimer) return;
    this.log(`Server core: restart in ${RESTART_DEBOUNCE_MS / 1000} s to apply the client change`, 'info');
    this.restartTimer = this.setTimeoutFn(() => { this.restartTimer = null; this.restart(); }, RESTART_DEBOUNCE_MS);
  }

  /* ----------------------------- the model ----------------------------- */

  /**
   * A model from the UI: normalised, validated, persisted, and applied with
   * a restart when the core runs. Errors come back with the normalised
   * model and nothing is persisted. The meter's numbers are the store's,
   * never the UI's copy (which is as old as its last fetch), and a client
   * the user switches back on loses the enforcer's reason.
   */
  async applyModel(next) {
    const current = this._model();
    const model = normalizeModel(next);
    const known = new Map();
    for (const i of current.inbounds) for (const c of i.clients) known.set(c.id, c);
    for (const i of model.inbounds) {
      for (const c of i.clients) {
        const k = known.get(c.id);
        if (k) c.used = { up: k.used.up, down: k.used.down };
        if (c.enabled) c.disabledBy = '';
      }
    }
    const v = validateModel(model, { servers: this.getServers() });
    if (!v.ok) return { ok: false, errors: v.errors, warnings: v.warnings, model };
    this.setModel(model);
    if (this.proc || this.startP) await this.restart();
    return { ok: true, errors: [], warnings: v.warnings, model };
  }
}

module.exports = { ServerCore, firewallArgs, parseServerVars, levelOf, exitReason };
