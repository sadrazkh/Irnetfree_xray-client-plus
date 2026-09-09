'use strict';
/**
 * The server core (plus, Server tab): one child process, a metrics poll,
 * the meter and the enforcer, the crash policy, and the channels on top.
 * Everything is driven by fakes — a fake spawn, a fake clock, a fake
 * /debug/vars — so no test here binds a socket or runs a core. The one
 * real thing is the shape of /debug/vars, copied from a live core.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');

const { ServerCore, firewallArgs, parseServerVars } = require('../src/main/xserver/core');
const { createXServer } = require('../src/main/xserver');
const X = require('../src/main/xserver/config');

const UUID = '5d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a';
const T0 = 1_800_000_000_000;

/** What xray 26.3.27 answers on /debug/vars after one request by "alice" (copied live). */
const VARS = {
  cmdline: [], memstats: {}, observatory: {},
  stats: {
    inbound: { 'probe-827b': { downlink: 0, uplink: 126 } },
    outbound: { block: { downlink: 0, uplink: 0 }, exit: { downlink: 808, uplink: 86 } },
    user: { alice: { downlink: 808, uplink: 86 } }
  }
};
const varsFor = (up, down) => ({ stats: { inbound: { 'main-in00': { uplink: up, downlink: down } }, user: { alice: { uplink: up, downlink: down } } } });

/* ----------------------------- fixtures ----------------------------- */

function client(over) {
  return Object.assign({ id: 'c000000000000001', enabled: true, email: 'alice', uuid: UUID }, over || {});
}
function inbound(over) {
  return Object.assign({
    id: 'in00000000000001', tag: 'main-in00', enabled: true, remark: 'Main', protocol: 'vless',
    listen: '127.0.0.1', port: 44443, network: 'tcp', security: 'none', clients: [client()]
  }, over || {});
}
function model(over) {
  return X.normalizeModel(Object.assign({ publicAddress: '127.0.0.1', inbounds: [inbound()] }, over || {}));
}

/** Promise chains and stream data need a couple of turns to land. */
const settle = () => new Promise(r => setImmediate(() => setImmediate(r)));

/** A clock whose timers fire only when the test advances it. */
function fakeClock(start = T0) {
  let t = start;
  const timers = [];
  return {
    now: () => t,
    setTimeout: (fn, ms) => { const h = { at: t + Math.max(0, ms | 0), fn }; timers.push(h); return h; },
    clearTimeout: (h) => { const i = timers.indexOf(h); if (i >= 0) timers.splice(i, 1); },
    pending: () => timers.length,
    async advance(ms) {
      const end = t + ms;
      for (;;) {
        timers.sort((a, b) => a.at - b.at);
        const next = timers[0];
        if (!next || next.at > end) break;
        timers.shift();
        t = next.at;
        next.fn();
        await settle();
      }
      t = end;
      await settle();
    }
  };
}

/** Stand-in for a spawned core: streams, a pid, and a kill() that exits it. */
function fakeChild(pid) {
  const p = new EventEmitter();
  p.pid = pid;
  p.stdout = new PassThrough();
  p.stderr = new PassThrough();
  p.killed = false;
  p.exited = false;
  p.exit = (code, signal) => { if (p.exited) return; p.exited = true; p.emit('exit', code, signal === undefined ? null : signal); };
  p.kill = () => { p.killed = true; setImmediate(() => p.exit(null, 'SIGTERM')); return true; };
  return p;
}

function fakeXray(over) {
  return Object.assign({
    validate: async () => ({ ok: true }),
    resolveEngine: (id) => ({ id: id || 'xray', bin: '/fake/bin/' + (id === 'xray-pattn' ? 'xray-pattn' : 'xray') }),
    binExists: (id) => id !== 'xray-pattn',
    spawnEnv: () => ({ FAKE_ENV: '1' }),
    assetDir: () => '/fake/bin'
  }, over || {});
}

function harness(over = {}) {
  const clock = fakeClock();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-xs-'));
  let stored = over.model || model();
  let sets = 0, queries = 0;
  const events = [], logs = [], notes = [], spawns = [], children = [];
  let vars = over.vars === undefined ? null : over.vars;
  let nextPid = 100;
  const spawn = (bin, args, opts) => {
    const c = fakeChild(++nextPid);
    spawns.push({ bin, args, opts, child: c });
    if (bin !== 'taskkill') children.push(c);
    return c;
  };
  const xray = fakeXray(over.xray);
  const core = new ServerCore(Object.assign({
    dataDir, xray,
    getModel: () => stored,
    setModel: (m) => { stored = m; sets++; },
    send: (ch, p) => events.push([ch, p]),
    log: (l, lv) => logs.push(`${lv || 'info'}: ${l}`),
    notify: (t, b) => notes.push(b),
    getServers: () => [],
    geoAvailable: () => true,
    spawn, now: clock.now, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    queryVars: async () => { queries++; return vars; },
    getFreePort: async () => 41000,
    platform: 'linux'
  }, over.core || {}));
  return {
    core, clock, dataDir, events, logs, notes, spawns, children, xray,
    model: () => stored,
    setVars: (v) => { vars = v; },
    sets: () => sets,
    queries: () => queries,
    last: () => children[children.length - 1],
    states: () => events.filter(e => e[0] === 'xserver-status').map(e => e[1].state),
    logEvents: () => events.filter(e => e[0] === 'xserver-log').map(e => e[1]),
    configFile: () => JSON.parse(fs.readFileSync(path.join(dataDir, 'xserver', 'config.json'), 'utf8')),
    cleanup: () => fs.rmSync(dataDir, { recursive: true, force: true })
  };
}

/** Run a test body against a harness and always remove its temp dir. */
function withCore(over, fn) {
  return async () => {
    const h = harness(over);
    try { await fn(h); } finally { h.cleanup(); }
  };
}

/* ----------------------------- start ----------------------------- */

test('start() validates the model first and does not spawn on an error', withCore({ model: model({ inbounds: [inbound({ clients: [client({ email: '' })] })] }) }, async (h) => {
  const r = await h.core.start();
  assert.equal(r.ok, false);
  assert.equal(r.error, 'inbounds[0].clients[0].email: a client needs a name');
  assert.equal(r.errors.length, 1);
  assert.equal(h.spawns.length, 0);
  const st = h.core.status();
  assert.equal(st.state, 'error');
  assert.equal(st.error, r.error);
  assert.equal(st.pid, null);
}));

test('start() runs the config through xray.validate and stops there on a refusal', async () => {
  let seen = null;
  const h = harness({ vars: VARS, xray: { validate: async (cfg) => { seen = cfg; return { ok: false, error: 'infra/conf: bad thing' }; } } });
  try {
    const r = await h.core.start();
    assert.deepEqual(r, { ok: false, error: 'infra/conf: bad thing' });
    assert.equal(h.spawns.length, 0);
    assert.equal(h.core.status().state, 'error');
    assert.equal(seen.metrics.listen, '127.0.0.1:41000', 'validated with the metrics port it will run on');
    assert.equal(seen.inbounds[0].tag, 'main-in00');
  } finally { h.cleanup(); }
  // an old core that does not know -test passes unverified, and that is fine
  const h2 = harness({ vars: VARS, xray: { validate: async () => ({ ok: true, unverified: true }) } });
  try {
    assert.deepEqual(await h2.core.start(), { ok: true });
    assert.equal(h2.spawns.length, 1);
  } finally { h2.cleanup(); }
});

test('start() writes <dataDir>/xserver/config.json, spawns like startTest does, and goes starting → running once the metrics port answers', withCore({ vars: VARS }, async (h) => {
  assert.deepEqual(await h.core.start(), { ok: true });
  const s = h.spawns[0];
  const cfgPath = path.join(h.dataDir, 'xserver', 'config.json');
  assert.equal(s.bin, '/fake/bin/xray');
  assert.deepEqual(s.args, ['run', '-c', cfgPath]);
  assert.equal(s.opts.cwd, '/fake/bin');
  assert.equal(s.opts.windowsHide, true);
  assert.equal(s.opts.env.FAKE_ENV, '1');
  const cfg = h.configFile();
  assert.equal(cfg.metrics.listen, '127.0.0.1:41000');
  assert.equal(cfg.inbounds[0].port, 44443);
  const st = h.core.status();
  assert.equal(st.state, 'running');
  assert.equal(st.pid, 101);
  assert.equal(st.since, h.clock.now());
  assert.equal(st.engine, 'xray');
  assert.equal(st.apiPort, 41000);
  assert.equal(st.error, '');
  assert.deepEqual(h.states(), ['starting', 'running']);
  assert.deepEqual(await h.core.start(), { ok: true, already: true }, 'a second start is a no-op');
  assert.equal(h.spawns.length, 1);
}));

test('starting waits for the metrics port, polling every 300 ms', withCore({ vars: null }, async (h) => {
  const p = h.core.start();
  await settle();
  assert.equal(h.core.status().state, 'starting');
  assert.equal(h.core.status().pid, 101);
  await h.clock.advance(900);
  assert.equal(h.core.status().state, 'starting');
  assert.equal(h.queries(), 4, 'one query at once, then one per 300 ms');
  h.setVars(VARS);
  await h.clock.advance(300);
  assert.deepEqual(await p, { ok: true });
  assert.equal(h.core.status().state, 'running');
  assert.equal(h.core.status().since, T0 + 1200);
}));

test('a child that exits before the metrics answer is a start error carrying the core\'s own reason', withCore({ vars: null }, async (h) => {
  const p = h.core.start();
  await settle();
  const c = h.last();
  c.stderr.write('Failed to start: main: failed to create server > app/proxyman/inbound: failed to listen TCP on 44443 > transport/internet: failed to listen on address: 127.0.0.1:44443 > bind: address already in use\n');
  await settle();
  c.exit(23);
  await settle();
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(r.error, 'bind: address already in use');
  const st = h.core.status();
  assert.equal(st.state, 'error');
  assert.equal(st.error, 'bind: address already in use');
  assert.equal(st.pid, null);
  assert.equal(h.clock.pending(), 0, 'nothing is left armed');
  assert.ok(h.logs.some(l => /^error: .*bind: address already in use/.test(l)));
}));

test('a core that never answers on its metrics port is killed and reported', withCore({ vars: null }, async (h) => {
  const p = h.core.start();
  await settle();
  await h.clock.advance(6300);
  const r = await p;
  assert.equal(r.ok, false);
  assert.match(r.error, /metrics port/);
  assert.equal(h.last().killed, true);
  assert.equal(h.core.status().state, 'error');
  assert.equal(h.core.status().pid, null);
  assert.equal(h.clock.pending(), 0);
}));

test('a spawn that fails is an error, not an exception', withCore({ vars: null }, async (h) => {
  const p = h.core.start();
  await settle();
  h.last().emit('error', new Error('spawn ENOENT'));
  await settle();
  const r = await p;
  assert.equal(r.ok, false);
  assert.match(r.error, /spawn ENOENT/);
  assert.equal(h.core.status().state, 'error');
}));

test('a stop() during starting wins: nothing runs afterwards', withCore({ vars: null }, async (h) => {
  const p = h.core.start();
  await settle();
  await h.core.stop();
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(h.core.status().state, 'stopped');
  assert.equal(h.spawns.length, 1);
  await h.clock.advance(20000);
  assert.equal(h.spawns.length, 1);
}));

/* ----------------------------- log ----------------------------- */

test('log lines go to the ring and to xserver-log with the level of xray\'s marker; the ring keeps 300', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  const c = h.last();
  c.stdout.write('2026/09/09 17:57:09 [Warning] core: Xray 26.3.27 started\n2026/09/09 17:57:11 [Info] from 127.0.0.1 accepted tcp:cp.cloudflare.com:80 [main-in00 >> exit] email: alice\n');
  c.stderr.write('2026/09/09 17:57:12 [Error] app/proxyman: something\n');
  c.stderr.write('partial line without');
  await settle();
  const ev = h.logEvents();
  assert.deepEqual(ev.map(e => e.level), ['warn', 'info', 'error']);
  assert.equal(ev[0].line, '2026/09/09 17:57:09 [Warning] core: Xray 26.3.27 started');
  assert.deepEqual(h.core.logLines(), ev.map(e => e.line), 'a partial line waits for its newline');
  c.stderr.write(' a newline\n');
  await settle();
  assert.equal(h.core.logLines().at(-1), 'partial line without a newline');
  for (let i = 0; i < 320; i++) c.stdout.write(`line ${i}\n`);
  await settle();
  assert.equal(h.core.logLines().length, 300);
  assert.equal(h.core.logLines()[0], 'line 20', '4 earlier lines + 320, the oldest 24 gone');
  assert.equal(h.core.logLines().at(-1), 'line 319');
}));

/* ----------------------------- crash policy ----------------------------- */

test('an exit while running restarts after 2 s, 5 s and 15 s, then gives up; the user is told once per incident', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  h.last().exit(2);
  await settle();
  assert.equal(h.core.status().state, 'error');
  assert.match(h.core.status().error, /restarting in 2 s/);
  assert.equal(h.spawns.length, 1);
  assert.equal(h.notes.length, 1);
  await h.clock.advance(1999);
  assert.equal(h.spawns.length, 1);
  await h.clock.advance(1);
  assert.equal(h.spawns.length, 2);
  assert.equal(h.core.status().state, 'running');
  assert.equal(h.core.status().pid, 102);

  h.last().exit(2);
  await settle();
  assert.match(h.core.status().error, /restarting in 5 s/);
  await h.clock.advance(4999);
  assert.equal(h.spawns.length, 2);
  await h.clock.advance(1);
  assert.equal(h.spawns.length, 3);

  h.last().exit(2);
  await settle();
  assert.match(h.core.status().error, /restarting in 15 s/);
  await h.clock.advance(15000);
  assert.equal(h.spawns.length, 4);
  assert.equal(h.core.status().state, 'running');

  h.last().stderr.write('panic: boom\n');
  await settle();
  h.last().exit(2);
  await settle();
  assert.equal(h.core.status().state, 'error');
  assert.equal(h.core.status().error, 'the core keeps exiting: panic: boom');
  await h.clock.advance(60000);
  assert.equal(h.spawns.length, 4, 'no more restarts');
  assert.equal(h.notes.length, 1, 'one notification for the whole incident');
  assert.equal(h.clock.pending(), 0);
}));

test('a core that stayed up for a minute starts a fresh incident when it dies again', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  for (let n = 0; n < 3; n++) {
    h.last().exit(1);
    await settle();
    await h.clock.advance(15000);
  }
  assert.equal(h.spawns.length, 4);
  assert.equal(h.core.status().state, 'running');
  await h.clock.advance(60000);      // twelve quiet ticks: the core is stable again
  h.last().exit(1);
  await settle();
  assert.match(h.core.status().error, /restarting in 2 s/, 'the back-off starts over');
  assert.equal(h.notes.length, 2, 'a new incident, a new notification');
  await h.clock.advance(2000);
  assert.equal(h.spawns.length, 5);
}));

test('stop() cancels the crash policy; an exit the user asked for is not a crash', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  h.last().exit(2);
  await settle();
  await h.clock.advance(1000);
  await h.core.stop();
  assert.equal(h.core.status().state, 'stopped');
  assert.equal(h.core.status().error, '');
  await h.clock.advance(60000);
  assert.equal(h.spawns.length, 1);
  assert.equal(h.clock.pending(), 0);

  await h.core.start();
  assert.equal(h.spawns.length, 2);
  await h.core.stop();
  await h.clock.advance(60000);
  assert.equal(h.spawns.length, 2);
  assert.equal(h.notes.length, 1, 'only the real crash was announced');
}));

/* ----------------------------- stop ----------------------------- */

test('stop() kills the child, waits for its exit, clears the tick; on win32 it also runs taskkill /t /f', withCore({ vars: VARS, core: { platform: 'win32' } }, async (h) => {
  await h.core.start();
  const c = h.last();
  const st = await h.core.stop();
  assert.equal(c.killed, true);
  const tk = h.spawns.find(s => s.bin === 'taskkill');
  assert.ok(tk, 'taskkill spawned');
  assert.deepEqual(tk.args, ['/pid', '101', '/t', '/f']);
  assert.equal(tk.opts.windowsHide, true);
  assert.equal(st.state, 'stopped');
  assert.equal(st.pid, null);
  assert.equal(st.since, 0);
  assert.equal(h.core.status().state, 'stopped');
  const q = h.queries();
  await h.clock.advance(30000);
  assert.equal(h.queries(), q, 'no tick after a stop');
  assert.equal(h.clock.pending(), 0);
  assert.equal((await h.core.stop()).state, 'stopped', 'a second stop is harmless');
}));

test('stop() gives up waiting after 3 s on a child that will not die, and ignores its late exit', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  const c = h.last();
  c.kill = () => true;
  const p = h.core.stop();
  await settle();
  await h.clock.advance(2999);
  assert.equal(h.core.status().state, 'running');
  await h.clock.advance(1);
  assert.equal((await p).state, 'stopped');
  c.exit(1);
  await settle();
  assert.equal(h.core.status().state, 'stopped');
  await h.clock.advance(30000);
  assert.equal(h.spawns.length, 1, 'a detached child\'s exit is not a crash');
}));

test('restart() is a stop and a start; the enforcer runs before the config is built', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  const r = await h.core.restart();
  assert.deepEqual(r, { ok: true });
  assert.equal(h.spawns.length, 2);
  assert.equal(h.core.status().pid, 102);
  assert.equal(h.core.status().state, 'running');
  // a client that ran out while the core was down leaves the config now, not a tick and a restart later
  h.model().inbounds[0].clients[0].expiresAt = T0 - 1;
  await h.core.restart();
  assert.deepEqual(h.configFile().inbounds[0].settings.clients, []);
  const c = h.model().inbounds[0].clients[0];
  assert.equal(c.enabled, false);
  assert.equal(c.disabledBy, 'expired');
  assert.equal(h.clock.pending(), 1, 'only the tick is armed: no restart is due');
}));

/* ----------------------------- the meter ----------------------------- */

test('a tick adds the /debug/vars user deltas to client.used, marks online, persists and emits status; a restart resets the baseline', withCore({ vars: VARS }, async (h) => {
  await h.core.start();
  const before = h.events.length;
  await h.clock.advance(5000);
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 86, down: 808 });
  assert.equal(h.sets(), 1);
  let st = h.core.status();
  assert.equal(st.inbounds[0].clients[0].online, true);
  assert.equal(st.inbounds[0].clients[0].up, 86);
  assert.equal(st.inbounds[0].clients[0].down, 808);
  assert.equal(st.inbounds[0].up, 86);
  assert.equal(st.inbounds[0].down, 808);
  assert.equal(st.inbounds[0].tag, 'main-in00');
  assert.equal(h.events[h.events.length - 1][0], 'xserver-status');
  assert.ok(h.events.length > before);

  h.setVars(varsFor(100, 1000));
  await h.clock.advance(5000);
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 100, down: 1000 });
  assert.equal(h.core.status().inbounds[0].clients[0].online, true);

  await h.clock.advance(5000);       // nothing moved
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 100, down: 1000 });
  assert.equal(h.core.status().inbounds[0].clients[0].online, false);
  assert.equal(h.sets(), 2, 'no write when nothing moved');

  // a metrics hiccup is skipped, not counted as zero
  h.setVars(null);
  await h.clock.advance(5000);
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 100, down: 1000 });

  // the new core's counters start at zero: the first reading is all new bytes
  h.setVars(varsFor(10, 20));
  await h.core.restart();
  await h.clock.advance(5000);
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 110, down: 1020 });
  assert.equal(h.core.status().state, 'running');
}));

test('a counter the model does not know is ignored', withCore({ vars: { stats: { user: { nobody: { uplink: 5, downlink: 5 } } } } }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  assert.deepEqual(h.model().inbounds[0].clients[0].used, { up: 0, down: 0 });
  assert.equal(h.sets(), 0);
}));

/* ----------------------------- the enforcer ----------------------------- */

test('quota reached: the client is disabled with disabledBy quota and one debounced restart applies it', withCore({ vars: VARS, model: model({ inbounds: [inbound({ clients: [client({ quotaBytes: 500 })] })] }) }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  const c = h.model().inbounds[0].clients[0];
  assert.equal(c.enabled, false);
  assert.equal(c.disabledBy, 'quota');
  assert.deepEqual(c.used, { up: 86, down: 808 });
  assert.ok(h.logs.some(l => /warn: .*"alice".*quota/.test(l)));
  const st = h.core.status().inbounds[0].clients[0];
  assert.equal(st.enabled, false);
  assert.equal(st.disabledBy, 'quota');
  assert.equal(h.spawns.length, 1);
  await h.clock.advance(5000);        // a second tick over quota does not arm a second restart
  await h.clock.advance(4999);
  assert.equal(h.spawns.length, 1);
  await h.clock.advance(1);
  assert.equal(h.spawns.length, 2, 'restarted 10 s after the change');
  assert.equal(h.core.status().state, 'running');
  assert.deepEqual(h.configFile().inbounds[0].settings.clients, [], 'the new config has no alice');
}));

test('expiry likewise; a future expiry is left alone', withCore({ vars: VARS, model: model({ inbounds: [inbound({ clients: [client({ expiresAt: T0 + 7000 })] })] }) }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  assert.equal(h.model().inbounds[0].clients[0].enabled, true);
  await h.clock.advance(5000);        // now T0 + 10000 > expiresAt
  const c = h.model().inbounds[0].clients[0];
  assert.equal(c.enabled, false);
  assert.equal(c.disabledBy, 'expired');
  await h.clock.advance(10000);
  assert.equal(h.spawns.length, 2);
}));

test('a bigger quota or a later expiry re-enables on the next tick', withCore({ vars: VARS, model: model({ inbounds: [inbound({ clients: [client({ quotaBytes: 500 })] })] }) }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  assert.equal(h.model().inbounds[0].clients[0].disabledBy, 'quota');
  await h.clock.advance(10000);       // the restart
  assert.equal(h.spawns.length, 2);
  h.model().inbounds[0].clients[0].quotaBytes = 1e9;
  await h.clock.advance(5000);
  const c = h.model().inbounds[0].clients[0];
  assert.equal(c.enabled, true);
  assert.equal(c.disabledBy, '');
  assert.ok(h.logs.some(l => /"alice".*enabled again/.test(l)));
  await h.clock.advance(10000);
  assert.equal(h.spawns.length, 3, 'and the restart puts alice back');
  assert.equal(h.configFile().inbounds[0].settings.clients.length, 1);
}));

test('a client the user disabled by hand is not the enforcer\'s business', withCore({ vars: VARS, model: model({ inbounds: [inbound({ clients: [client({ enabled: false, quotaBytes: 1 })] })] }) }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  const c = h.model().inbounds[0].clients[0];
  assert.equal(c.enabled, false);
  assert.equal(c.disabledBy, '');
  assert.equal(h.clock.pending(), 1, 'only the tick, no restart');
}));

/* ----------------------------- applyModel ----------------------------- */

test('applyModel: errors come back without persisting; a valid model is persisted, normalised, and restarts a running core', withCore({ vars: VARS }, async (h) => {
  const bad = await h.core.applyModel({ inbounds: [inbound({ clients: [client({ email: '' })] })] });
  assert.equal(bad.ok, false);
  assert.equal(bad.errors[0].path, 'inbounds[0].clients[0].email');
  assert.equal(bad.model.inbounds[0].clients[0].uuid, UUID, 'the rejected model comes back normalised so the form keeps its values');
  assert.equal(h.sets(), 0);

  const good = await h.core.applyModel(Object.assign({}, h.model(), { blockTorrent: true, logLevel: 'debug' }));
  assert.equal(good.ok, true);
  assert.deepEqual(good.errors, []);
  assert.deepEqual(good.warnings, []);
  assert.equal(good.model.blockTorrent, true);
  assert.equal(h.model().blockTorrent, true);
  assert.equal(h.sets(), 1);
  assert.equal(h.spawns.length, 0, 'stopped: nothing to restart');

  await h.core.start();
  assert.equal(h.configFile().log.loglevel, 'debug');
  const again = await h.core.applyModel(Object.assign({}, h.model(), { logLevel: 'info' }));
  assert.equal(again.ok, true);
  assert.equal(h.spawns.length, 2, 'running: restarted');
  assert.equal(h.core.status().state, 'running');
  assert.equal(h.configFile().log.loglevel, 'info');

  const quiet = await h.core.applyModel(Object.assign({}, h.model(), { publicAddress: '203.0.113.7', autoStart: true }));
  assert.equal(quiet.ok, true);
  assert.equal(h.spawns.length, 2, 'a change the core would not see does not restart it');

  const warned = await h.core.applyModel(Object.assign({}, h.model(), { inbounds: [inbound({ clients: [] })] }));
  assert.equal(warned.ok, true);
  assert.equal(warned.warnings[0].path, 'inbounds[0].clients');
}));

test('applyModel keeps the meter\'s numbers and clears disabledBy when the user re-enables a client', withCore({ vars: VARS, model: model({ inbounds: [inbound({ clients: [client({ quotaBytes: 500 })] })] }) }, async (h) => {
  await h.core.start();
  await h.clock.advance(5000);
  const c0 = h.model().inbounds[0].clients[0];
  assert.deepEqual(c0.used, { up: 86, down: 808 });
  assert.equal(c0.disabledBy, 'quota');
  // the renderer's copy is as old as its last fetch: zero bytes, still enabled
  const stale = JSON.parse(JSON.stringify(h.model()));
  stale.inbounds[0].clients[0].used = { up: 0, down: 0 };
  stale.inbounds[0].clients[0].note = 'edited';
  const r = await h.core.applyModel(stale);
  assert.equal(r.ok, true);
  const c1 = h.model().inbounds[0].clients[0];
  assert.deepEqual(c1.used, { up: 86, down: 808 }, 'the store\'s numbers win');
  assert.equal(c1.note, 'edited');
  assert.equal(c1.enabled, false);
  assert.equal(c1.disabledBy, 'quota', 'the reason still holds, so the client stays out');

  // the user raises the quota and switches the client back on
  const on = JSON.parse(JSON.stringify(h.model()));
  on.inbounds[0].clients[0].enabled = true;
  on.inbounds[0].clients[0].quotaBytes = 1e9;
  await h.core.applyModel(on);
  const c2 = h.model().inbounds[0].clients[0];
  assert.equal(c2.enabled, true);
  assert.equal(c2.disabledBy, '');
  assert.equal(h.configFile().inbounds[0].settings.clients.length, 1, 'and the restarted core carries the client');

  // switched on again without a bigger quota: the enforcer takes it out at once
  const again = JSON.parse(JSON.stringify(h.model()));
  again.inbounds[0].clients[0].quotaBytes = 500;
  await h.core.applyModel(again);
  const c3 = h.model().inbounds[0].clients[0];
  assert.equal(c3.enabled, false);
  assert.equal(c3.disabledBy, 'quota');
  assert.deepEqual(h.configFile().inbounds[0].settings.clients, []);
}));

/* ----------------------------- pure helpers ----------------------------- */

test('parseServerVars reads the inbound and user counters as /debug/vars nests them', () => {
  assert.deepEqual(parseServerVars(VARS), {
    inbounds: { 'probe-827b': { up: 126, down: 0 } },
    users: { alice: { up: 86, down: 808 } }
  });
  assert.deepEqual(parseServerVars(null), { inbounds: {}, users: {} });
  assert.deepEqual(parseServerVars({ stats: {} }), { inbounds: {}, users: {} });
  assert.deepEqual(parseServerVars({ stats: { user: { bob: { uplink: 'x' } }, inbound: null } }), { inbounds: {}, users: { bob: { up: 0, down: 0 } } });
});

test('firewallArgs are the exact netsh argument arrays', () => {
  assert.deepEqual(firewallArgs('IRNetFree Plus vless-reality-a1b2', 443, true),
    ['advfirewall', 'firewall', 'add', 'rule', 'name=IRNetFree Plus vless-reality-a1b2', 'dir=in', 'action=allow', 'protocol=TCP', 'localport=443']);
  assert.deepEqual(firewallArgs('IRNetFree Plus vless-reality-a1b2', 443, false),
    ['advfirewall', 'firewall', 'delete', 'rule', 'name=IRNetFree Plus vless-reality-a1b2']);
});

test('status() when nothing ever ran: stopped, and the model\'s lifetime totals', () => {
  const h = harness({ model: model({ inbounds: [inbound({ clients: [client({ used: { up: 5, down: 7 } }), client({ id: 'c2', email: 'bob', uuid: UUID, used: { up: 1, down: 1 } })] })] }) });
  try {
    const st = h.core.status();
    assert.equal(st.state, 'stopped');
    assert.equal(st.pid, null);
    assert.equal(st.since, 0);
    assert.equal(st.apiPort, 0);
    assert.equal(st.error, '');
    assert.equal(st.inbounds.length, 1);
    assert.equal(st.inbounds[0].up, 6);
    assert.equal(st.inbounds[0].down, 8);
    assert.deepEqual(st.inbounds[0].clients.map(c => c.email), ['alice', 'bob']);
    assert.equal(st.inbounds[0].clients[0].online, false);
    assert.deepEqual(h.core.logLines(), []);
  } finally { h.cleanup(); }
});

/* ----------------------------- channels ----------------------------- */

const X25519_OUT = 'PrivateKey: kFvXdm68IgR_KI7ymjyZFAA0klivp9_bzTzG_ZTEMUs\nPassword (PublicKey): Jd9XoO4GctsG_3hbVV-phXXqp-D1I02WXJUJhtVlq34\nHash32: SKPw6gZxdbSDqIitiREa5JcbLxSKcBXVvBmRU0C-GvI\n';

function fakeCtx(over = {}) {
  const handlers = {}, events = [], logs = [], notes = [], lazy = [];
  const data = Object.assign({}, over.data || {});
  const store = {
    get: (k, d) => (k in data ? data[k] : d),
    set: (k, v) => { data[k] = v; },
    setLazy: (k, v) => { data[k] = v; lazy.push(k); return true; },
    data
  };
  return Object.assign({
    handle: (ch, fn) => { handlers[ch] = fn; },
    send: (ch, p) => events.push([ch, p]),
    notify: (t, b) => notes.push([t, b]),
    store, dataDir: over.dataDir, getSettings: () => ({}), xray: fakeXray(over.xray),
    getServers: () => over.servers || [],
    addServer: () => {},
    resolveTarget: () => null,
    log: (l, lv) => logs.push(`${lv || 'info'}: ${l}`),
    platform: over.platform || 'linux', isElectron: false,
    handlers, events, logs, notes, lazy
  }, over.ctx || {});
}

function channels(over = {}) {
  const clock = fakeClock();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-xsc-'));
  const ctx = fakeCtx(Object.assign({ dataDir }, over));
  const execs = [];
  const spawns = [];
  let vars = over.vars === undefined ? VARS : over.vars;
  const xs = createXServer(ctx, {
    execFile: (bin, args, opts, cb) => {
      execs.push({ bin, args, opts });
      const r = over.exec ? over.exec(bin, args) : { stdout: '' };
      setImmediate(() => (r.error ? cb(r.error, r.stdout || '', r.stderr || '') : cb(null, r.stdout || '', r.stderr || '')));
    },
    setTimeout: clock.setTimeout,
    core: {
      spawn: (bin, args, opts) => { const c = fakeChild(300 + spawns.length); spawns.push({ bin, args, opts, child: c }); return c; },
      now: clock.now, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
      queryVars: async () => vars, getFreePort: async () => 41000, platform: ctx.platform
    }
  });
  xs.register();
  return {
    ctx, xs, clock, execs, spawns,
    call: (ch, arg) => ctx.handlers[ch](arg),
    cleanup: () => fs.rmSync(dataDir, { recursive: true, force: true })
  };
}

function withChannels(over, fn) {
  return async () => {
    const h = channels(over);
    try { await fn(h); } finally { h.cleanup(); }
  };
}

test('register() installs every channel of spec 2.4', withChannels({}, async (h) => {
  const want = ['get', 'set', 'start', 'stop', 'restart', 'status', 'log', 'genKeys', 'genId', 'clientLink', 'preview', 'otherSide', 'firewall'].map(c => 'xserver:' + c);
  assert.deepEqual(Object.keys(h.ctx.handlers).sort(), want.sort());
}));

test('xserver:get — the model from the store (normalised), the status, and which engines are installed', withChannels({ data: { xserver: { publicAddress: 'vpn.example.com', inbounds: [inbound()] } } }, async (h) => {
  const r = await h.call('xserver:get');
  assert.equal(r.model.publicAddress, 'vpn.example.com');
  assert.equal(r.model.inbounds[0].clients[0].used.up, 0, 'normalised');
  assert.equal(r.status.state, 'stopped');
  assert.deepEqual(r.engines, [
    { id: 'xray', label: 'Xray (official)', installed: true },
    { id: 'xray-pattn', label: 'Xray-PattN (patterniha)', installed: false }
  ]);
  // an empty store is the default model, not an error
  const empty = channels({});
  try { assert.deepEqual((await empty.call('xserver:get')).model, X.DEFAULT_MODEL); } finally { empty.cleanup(); }
}));

test('xserver:set — validates, persists through store.setLazy, restarts when running, and returns the status', withChannels({}, async (h) => {
  const bad = await h.call('xserver:set', { inbounds: [inbound({ port: 0 })] });
  assert.equal(bad.ok, false);
  assert.equal(bad.errors[0].path, 'inbounds[0].port');
  assert.equal(bad.status.state, 'stopped');
  assert.deepEqual(h.ctx.lazy, []);

  const good = await h.call('xserver:set', model({ blockTorrent: true }));
  assert.equal(good.ok, true);
  assert.deepEqual(h.ctx.lazy, ['xserver']);
  assert.equal(h.ctx.store.data.xserver.blockTorrent, true);
  assert.equal(good.model.blockTorrent, true);
  assert.equal(good.status.state, 'stopped');

  const st = await h.call('xserver:start');
  assert.equal(st.ok, true);
  assert.equal(st.state, 'running');
  assert.equal(h.spawns.length, 1);
  const again = await h.call('xserver:set', model({ blockTorrent: false }));
  assert.equal(again.ok, true);
  assert.equal(again.status.state, 'running');
  assert.equal(h.spawns.length, 2);
}));

test('xserver:start / stop / restart / status / log', withChannels({}, async (h) => {
  const s0 = await h.call('xserver:status');
  assert.equal(s0.state, 'stopped');
  const s1 = await h.call('xserver:start');
  assert.equal(s1.ok, true);
  assert.equal(s1.error, '');
  assert.equal(s1.state, 'running');
  assert.equal(s1.pid, 300);
  const s2 = await h.call('xserver:restart');
  assert.equal(s2.ok, true);
  assert.equal(s2.pid, 301);
  h.spawns[1].child.stdout.write('2026/09/09 [Warning] core: Xray started\n');
  await settle();
  assert.deepEqual(await h.call('xserver:log'), ['2026/09/09 [Warning] core: Xray started']);
  const s3 = await h.call('xserver:stop');
  assert.equal(s3.state, 'stopped');
  assert.equal(s3.ok, undefined);
  // a failing start says why, on top of the status
  h.ctx.store.data.xserver = { inbounds: [inbound({ clients: [client({ email: '' })] })] };
  const s4 = await h.call('xserver:start');
  assert.equal(s4.ok, false);
  assert.match(s4.error, /a client needs a name/);
  assert.equal(s4.state, 'error');
  assert.ok(h.ctx.logs.some(l => /^error: Server core: /.test(l)));
}));

test('xserver:genKeys runs <engine> x25519 and parses the 26.x output', async () => {
  const h = channels({ data: { xserver: { engine: 'xray-pattn' } }, exec: () => ({ stdout: X25519_OUT }) });
  try {
    const r = await h.call('xserver:genKeys');
    assert.deepEqual(r, { privateKey: 'kFvXdm68IgR_KI7ymjyZFAA0klivp9_bzTzG_ZTEMUs', publicKey: 'Jd9XoO4GctsG_3hbVV-phXXqp-D1I02WXJUJhtVlq34' });
    assert.equal(h.execs[0].bin, '/fake/bin/xray-pattn', 'the model\'s engine');
    assert.deepEqual(h.execs[0].args, ['x25519']);
    assert.equal(h.execs[0].opts.windowsHide, true);
  } finally { h.cleanup(); }
  const none = channels({ xray: { resolveEngine: () => ({ id: 'xray', bin: null }) } });
  try { assert.deepEqual(await none.call('xserver:genKeys'), { error: 'core binary not found' }); } finally { none.cleanup(); }
  const broken = channels({ exec: () => ({ error: new Error('spawn EACCES') }) });
  try { assert.deepEqual(await broken.call('xserver:genKeys'), { error: 'spawn EACCES' }); } finally { broken.cleanup(); }
  const garbage = channels({ exec: () => ({ stdout: 'nothing useful' }) });
  try { assert.match((await garbage.call('xserver:genKeys')).error, /key pair/); } finally { garbage.cleanup(); }
});

test('xserver:genId — uuid, password, shortId, ss2022:<method>', withChannels({}, async (h) => {
  assert.match((await h.call('xserver:genId', 'uuid')).value, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match((await h.call('xserver:genId', 'password')).value, /^[A-Za-z0-9_-]{22}$/);
  assert.match((await h.call('xserver:genId', 'shortId')).value, /^[0-9a-f]{16}$/);
  const k16 = (await h.call('xserver:genId', 'ss2022:2022-blake3-aes-128-gcm')).value;
  assert.equal(Buffer.from(k16, 'base64').length, 16);
  const k32 = (await h.call('xserver:genId', 'ss2022:2022-blake3-aes-256-gcm')).value;
  assert.equal(Buffer.from(k32, 'base64').length, 32);
  assert.match((await h.call('xserver:genId', 'ss2022:rot13')).error, /unknown method/);
  assert.match((await h.call('xserver:genId', 'lottery')).error, /unknown kind/);
  assert.notEqual((await h.call('xserver:genId', 'uuid')).value, (await h.call('xserver:genId', 'uuid')).value);
}));

test('xserver:clientLink — the link and the client-side record, or why not', withChannels({ data: { xserver: { publicAddress: 'vpn.example.com', inbounds: [inbound()] } } }, async (h) => {
  const r = await h.call('xserver:clientLink', { inboundId: 'in00000000000001', clientId: 'c000000000000001' });
  assert.match(r.link, /^vless:\/\/5d1a7e3c-4b0f-4a6e-9c1d-1f2e3d4c5b6a@vpn\.example\.com:44443\?/);
  assert.equal(r.record.address, 'vpn.example.com');
  assert.equal(r.record.port, 44443);
  assert.equal(r.record.outbound.protocol, 'vless');
  assert.deepEqual(await h.call('xserver:clientLink', { inboundId: 'nope', clientId: 'c000000000000001' }), { error: 'inbound not found' });
  assert.deepEqual(await h.call('xserver:clientLink', { inboundId: 'in00000000000001', clientId: 'nope' }), { error: 'client not found' });
  assert.deepEqual(await h.call('xserver:clientLink'), { error: 'inbound not found' });
  h.ctx.store.data.xserver.publicAddress = '';
  assert.deepEqual(await h.call('xserver:clientLink', { inboundId: 'in00000000000001', clientId: 'c000000000000001' }), { error: 'no public address' });
}));

test('xserver:preview — the config that would run; the metrics port is a stand-in until the core runs', withChannels({ data: { xserver: model() } }, async (h) => {
  const p = await h.call('xserver:preview');
  assert.equal(p.config.metrics.listen, '127.0.0.1:10099');
  assert.equal(p.config.inbounds[0].settings.clients[0].id, UUID, 'secrets included: it is the user\'s own server');
  await h.call('xserver:start');
  assert.equal((await h.call('xserver:preview')).config.metrics.listen, '127.0.0.1:41000');
}));

test('xserver:otherSide — the snippet for the other end of the reverse pair', withChannels({ data: { xserver: model() } }, async (h) => {
  assert.deepEqual(await h.call('xserver:otherSide'), { role: null, snippet: null, link: null });
  h.ctx.store.data.xserver = model({ reverse: { role: 'bridge', bridge: { via: 'link', link: '' } } });
  assert.match((await h.call('xserver:otherSide')).error, /no usable portal target/);
  const ic = inbound();
  h.ctx.store.data.xserver = model({ inbounds: [ic, inbound({ id: 'in00000000000002', tag: 'users-in02', port: 44444 })], reverse: { role: 'portal', portal: { interconnInboundId: ic.id, userInboundIds: ['in00000000000002'] } } });
  const r = await h.call('xserver:otherSide');
  assert.equal(r.role, 'bridge');
  assert.match(r.link, /^vless:\/\//);
  assert.equal(r.snippet.outbounds[0].settings.reverse.tag, 'bridge');
}));

test('xserver:firewall — netsh on Windows, only when asked; unsupported elsewhere', async () => {
  const linux = channels({ data: { xserver: model() } });
  try {
    assert.deepEqual(await linux.call('xserver:firewall', { inboundId: 'in00000000000001', allow: true }), { ok: false, error: 'unsupported' });
    assert.equal(linux.execs.length, 0);
  } finally { linux.cleanup(); }
  const win = channels({ platform: 'win32', data: { xserver: model() } });
  try {
    assert.deepEqual(await win.call('xserver:firewall', { inboundId: 'in00000000000001', allow: true }), { ok: true });
    assert.equal(win.execs[0].bin, 'netsh');
    assert.deepEqual(win.execs[0].args, ['advfirewall', 'firewall', 'add', 'rule', 'name=IRNetFree Plus main-in00', 'dir=in', 'action=allow', 'protocol=TCP', 'localport=44443']);
    assert.deepEqual(await win.call('xserver:firewall', { inboundId: 'in00000000000001', allow: false }), { ok: true });
    assert.deepEqual(win.execs[1].args, ['advfirewall', 'firewall', 'delete', 'rule', 'name=IRNetFree Plus main-in00']);
    assert.deepEqual(await win.call('xserver:firewall', { inboundId: 'nope', allow: true }), { ok: false, error: 'inbound not found' });
    assert.equal(win.execs.length, 2);
  } finally { win.cleanup(); }
  const denied = channels({ platform: 'win32', data: { xserver: model() }, exec: () => ({ error: new Error('exit 1'), stdout: 'The requested operation requires elevation.\r\n' }) });
  try {
    assert.deepEqual(await denied.call('xserver:firewall', { inboundId: 'in00000000000001', allow: true }), { ok: false, error: 'The requested operation requires elevation.' });
  } finally { denied.cleanup(); }
});

test('a handler that throws answers { ok:false, error } instead of breaking the bridge', withChannels({ xray: { binExists: () => { throw new Error('boom'); } } }, async (h) => {
  assert.deepEqual(await h.call('xserver:get'), { ok: false, error: 'boom' });
}));

test('autoStart() starts the core 1.5 s later only when the model says so; stop() is the quit path', async () => {
  const off = channels({ data: { xserver: model() } });
  try {
    off.xs.autoStart();
    assert.equal(off.clock.pending(), 0);
  } finally { off.cleanup(); }
  const on = channels({ data: { xserver: model({ autoStart: true }) } });
  try {
    on.xs.autoStart();
    assert.equal(on.clock.pending(), 1);
    await on.clock.advance(1499);
    assert.equal(on.spawns.length, 0);
    await on.clock.advance(1);
    assert.equal(on.spawns.length, 1);
    assert.equal(on.xs.status().state, 'running');
    await on.xs.stop();
    assert.equal(on.xs.status().state, 'stopped');
    assert.equal(on.spawns[0].child.killed, true);
  } finally { on.cleanup(); }
});

test('events: xserver-status on every state change and tick, xserver-log per line; the log names start, stop and enforcer actions', withChannels({ data: { xserver: model({ inbounds: [inbound({ clients: [client({ quotaBytes: 10 })] })] }) } }, async (h) => {
  await h.call('xserver:start');
  assert.deepEqual(h.ctx.events.filter(e => e[0] === 'xserver-status').map(e => e[1].state), ['starting', 'running']);
  await h.clock.advance(5000);
  const last = h.ctx.events.filter(e => e[0] === 'xserver-status').at(-1)[1];
  assert.equal(last.inbounds[0].clients[0].disabledBy, 'quota');
  assert.ok(h.ctx.logs.some(l => /Server core: starting/.test(l)));
  assert.ok(h.ctx.logs.some(l => /"alice".*quota/.test(l)));
  assert.ok(h.ctx.logs.some(l => /restart in 10 s/.test(l)));
  assert.equal(h.ctx.notes.length, 0, 'no notification for a planned thing');
  h.spawns[0].child.exit(9);
  await settle();
  assert.equal(h.ctx.notes.length, 1);
  assert.equal(h.ctx.notes[0][0], 'IRNetFree Plus');
  await h.xs.stop();
}));
