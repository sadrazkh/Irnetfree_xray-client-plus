'use strict';
/**
 * IP-scan ranking. Pure arithmetic, so the tests pin the formula itself:
 * more download is better, loss and latency and jitter all pull a score down,
 * the latency the score sees is the median (one slow sample must not sink a
 * good IP), a tunnel that never answered scores 0, and a TCP-only scan still
 * ranks.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { scoreResult, delayStats } = require('../src/main/scan/score');

const close = (a, b, msg) => assert.ok(Math.abs(a - b) < 1e-9, `${msg || ''} ${a} vs ${b}`);

test('delayStats: min/median/avg over the successes, loss over all, jitter = mean absolute deviation', () => {
  const s = delayStats([50, 70, -1]);
  assert.deepEqual(Object.keys(s).sort(), ['avg', 'jitter', 'loss', 'median', 'min', 'samples']);
  assert.equal(s.min, 50);
  assert.equal(s.median, 60);
  assert.equal(s.avg, 60);
  close(s.loss, 1 / 3);
  assert.equal(s.jitter, 10);
  assert.deepEqual(s.samples, [50, 70, -1]);
});

test('delayStats: the median is the middle success, so one slow sample does not move it; an even count takes the mean of the middle two', () => {
  const slow = delayStats([40, 42, 900]);
  assert.equal(slow.median, 42);
  assert.equal(slow.avg, 327.3);
  assert.equal(delayStats([40, 60, 80, 100]).median, 70);
  assert.equal(delayStats([80, -1, 40, 60]).median, 60, 'failed samples are not in the middle');
  assert.equal(delayStats([900, 40, 42]).median, 42, 'order of arrival does not matter');
});

test('delayStats: one success has no jitter; no success is loss 1 with zeroed fields; empty input too', () => {
  assert.deepEqual(delayStats([120]), { min: 120, median: 120, avg: 120, jitter: 0, loss: 0, samples: [120] });
  assert.deepEqual(delayStats([-1, -1]), { min: 0, median: 0, avg: 0, jitter: 0, loss: 1, samples: [-1, -1] });
  assert.deepEqual(delayStats([]), { min: 0, median: 0, avg: 0, jitter: 0, loss: 1, samples: [] });
  assert.deepEqual(delayStats(null).loss, 1);
});

test('delayStats rounds avg, median and jitter to one decimal', () => {
  const s = delayStats([10, 11, 13]);
  assert.equal(s.avg, 11.3);
  assert.equal(s.median, 11);
  assert.equal(s.jitter, 1.1);      // deviations 1.333, 0.333, 1.667 → mean 1.111
  assert.equal(delayStats([10, 11, 12, 15]).median, 11.5);
});

const delay = (median, jitter = 0, loss = 0, min = median) => ({ min, median, avg: median, jitter, loss, samples: [] });
const down = (mbps, ok = true) => ({ ok, bytes: 0, ms: 0, ttfb: 0, mbps, mbpsRaw: mbps, warm: true, error: ok ? null : 'timeout' });

test('the formula: base × (1 − loss) / (1 + median/200) / (1 + jitter/100), base = 100 × Mbps, one decimal', () => {
  // 100 × 10 = 1000 → / (1 + 100/200) / (1 + 20/100) = 1000 / 1.5 / 1.2
  assert.equal(scoreResult({ delay: delay(100, 20, 0), down: down(10) }), 555.6);
  // a third lost
  assert.equal(scoreResult({ delay: delay(100, 20, 1 / 3), down: down(10) }), 370.4);
  // nothing to penalise
  assert.equal(scoreResult({ delay: delay(0, 0, 0), down: down(2.5) }), 250);
});

test('the latency term is the median, not the mean; a row from before the median existed still ranks by its mean', () => {
  const stats = delayStats([40, 42, 900]);                       // median 42, mean 327.3
  const byMedian = scoreResult({ delay: Object.assign({}, stats, { jitter: 0 }) });
  assert.equal(byMedian, 826.4);                                   // 1000 / (1 + 42/200)
  assert.ok(byMedian > 1000 / (1 + 327.3 / 200) + 400, 'the mean would have halved it');
  assert.equal(scoreResult({ delay: { min: 0, avg: 200, jitter: 0, loss: 0, samples: [] } }), 500);
});

test('more download is a higher score; latency, jitter and loss lower it', () => {
  const base = scoreResult({ delay: delay(100, 10, 0), down: down(10) });
  assert.ok(scoreResult({ delay: delay(100, 10, 0), down: down(20) }) > base, 'download');
  assert.ok(scoreResult({ delay: delay(200, 10, 0), down: down(10) }) < base, 'latency');
  assert.ok(scoreResult({ delay: delay(100, 40, 0), down: down(10) }) < base, 'jitter');
  assert.ok(scoreResult({ delay: delay(100, 10, 0.5), down: down(10) }) < base, 'loss');
});

test('delay-only mode uses base 1000', () => {
  assert.equal(scoreResult({ delay: delay(0, 0, 0), down: null }), 1000);
  assert.equal(scoreResult({ delay: delay(200, 0, 0) }), 500);
  assert.equal(scoreResult({ delay: delay(200, 100, 0) }), 250);
});

test('no successful delay sample scores 0, whatever else was measured', () => {
  assert.equal(scoreResult({ delay: delay(0, 0, 1), down: down(50) }), 0);
  assert.equal(scoreResult({ delay: delayStats([-1, -1, -1]), tcp: { ok: true, ms: 5 } }), 0);
});

test('a download that was tested and failed scores 0 — it must not outrank a slow working one', () => {
  assert.equal(scoreResult({ delay: delay(50), down: down(0, false) }), 0);
  assert.ok(scoreResult({ delay: delay(50), down: down(0.5) }) > 0);
});

test('TCP-only: 1000 / (1 + ms/50), so a TCP-only scan still ranks; a failed connect is 0', () => {
  assert.equal(scoreResult({ tcp: { ok: true, ms: 0 } }), 1000);
  assert.equal(scoreResult({ tcp: { ok: true, ms: 50 } }), 500);
  assert.equal(scoreResult({ tcp: { ok: true, ms: 200 } }), 200);
  assert.equal(scoreResult({ tcp: { ok: false, ms: -1, error: 'timeout' } }), 0);
  assert.equal(scoreResult({ tcp: null, delay: null, down: null, up: null }), 0);
  assert.equal(scoreResult(null), 0);
  assert.equal(scoreResult({ error: 'spawn failed' }), 0);
});

test('download without delay: the download alone is the base', () => {
  assert.equal(scoreResult({ tcp: { ok: true, ms: 30 }, down: down(4) }), 400);
});
