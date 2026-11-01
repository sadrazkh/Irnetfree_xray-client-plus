'use strict';
/**
 * scripts/validate-configs.js without a core (IRNF_VALIDATE_DRY=1): every
 * server shape and every scan shape is built and written for the suggested
 * Xray, so the generation itself is checked on every platform; CI's `cores`
 * job hands the same files to the real cores.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('the dry run builds every server and scan shape — MASQUE, WARP and ECH among them — and writes each one', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-plus-dry-'));
  try {
    const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'validate-configs.js')], {
      env: Object.assign({}, process.env, { IRNF_VALIDATE_DRY: '1', IRNF_VALIDATE_OUT: out }), encoding: 'utf8', timeout: 60000
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const built = r.stdout.split(/\r?\n/).filter(l => l.startsWith('built ')).map(l => l.slice(6));
    assert.equal(fs.readdirSync(out).length, built.length, 'every config it names is on disk');
    assert.match(r.stdout, /configs built for xray \d+\.\d+\.\d+ \((\d+) server shapes, (\d+) scan shapes\)/);
    const [, srv, scan] = /\((\d+) server shapes, (\d+) scan shapes\)/.exec(r.stdout).map(Number);
    assert.ok(srv >= 40, 'server shapes: ' + srv);
    assert.equal(scan, 21);
    for (const name of ['scan-masque-h3', 'scan-masque-h2', 'scan-warp-h3', 'scan-warp-h2-cover', 'scan-vless-ws-tls-ech', 'scan-hy2-salamander-hop', 'scan-wireguard', 'scan-json-fragment',
      'scan-vless-ws-tls-dialmode', 'scan-pattn-vless-ws-tls-merge', 'scan-pattn-trojan-tcp-tls-merge-dialmode', 'scan-pattn-vless-ws-tls-tlshello-0-len']) {
      assert.ok(built.includes(name + '.json'), name);
    }
    // Xray-PattN's dial tricks survive applyTarget and adaptForCore on every variant (upstream v1.41)
    const oob = JSON.parse(fs.readFileSync(path.join(out, 'scan-vless-ws-tls-dialmode.json'), 'utf8'));
    assert.deepEqual(oob.outbounds.filter(o => o.protocol === 'vless').map(o => o.streamSettings.sockopt.dialMode), ['oob.0', 'oob.0', 'oob.0', 'oob.0']);
    const merge = JSON.parse(fs.readFileSync(path.join(out, 'scan-pattn-trojan-tcp-tls-merge-dialmode.json'), 'utf8'));
    for (const o of merge.outbounds.filter(o => o.protocol === 'trojan')) {
      assert.equal(o.streamSettings.sockopt.dialMode, 'oob.0');
      assert.equal(o.streamSettings.finalmask.tcp[0].type, 'merge');
    }
    // the scan core of an SNI-able config carries the four variants; REALITY's three (no SNI)
    const ws = JSON.parse(fs.readFileSync(path.join(out, 'scan-vless-ws-tls.json'), 'utf8'));
    assert.equal(ws.inbounds.length, 4);
    assert.deepEqual(ws.outbounds.filter(o => o.protocol === 'vless').map(o => o.settings.vnext[0].address), ['104.16.0.1', '2606:4700::1', '104.16.0.2', '104.16.0.3']);
    assert.equal(ws.outbounds[3].streamSettings.tlsSettings.serverName, 'front.example.org');
    const reality = JSON.parse(fs.readFileSync(path.join(out, 'scan-vless-reality-vision.json'), 'utf8'));
    assert.equal(reality.inbounds.length, 3);
    const wg = JSON.parse(fs.readFileSync(path.join(out, 'scan-wireguard.json'), 'utf8'));
    assert.equal(wg.outbounds[1].settings.peers[0].endpoint, '[2606:4700::1]:2408');
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});
