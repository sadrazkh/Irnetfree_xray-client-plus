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

const { scoreResult, delayStats, passes, needOf, reasonOf, latencyPoints, PASS_RATIO } = require('../src/main/scan/score');

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

const down = (mbps, ok = true, ttfb = 0) => ({ ok, bytes: 0, ms: 0, ttfb, mbps, mbpsRaw: mbps, warm: true, error: ok ? null : 'timeout' });

test('the formula: 100 × success% + round(99 / (1 + median/200)) — the page shows it / 100', () => {
  assert.equal(latencyPoints(0), 99);
  assert.equal(latencyPoints(200), 50);
  assert.equal(latencyPoints(400), 33);
  assert.equal(latencyPoints(1e9), 0);
  assert.equal(scoreResult({ delay: delayStats([100, 120, 140]) }), 10000 + 62);    // median 120
  assert.equal(scoreResult({ delay: delayStats([100, -1, 140]) }), 6700 + 62);       // 2 of 3, median 120
  assert.equal(scoreResult({ delay: delayStats([0, 0, 0]) }), 10099);
});

test('success first: three of three at 400 ms beats two of three at 20 ms; then the faster median wins', () => {
  const steady = scoreResult({ delay: delayStats([380, 400, 420]) });
  const lucky = scoreResult({ delay: delayStats([20, 20, -1]) });
  assert.ok(steady > lucky, `${steady} > ${lucky}`);
  assert.ok(scoreResult({ delay: delayStats([90, 100, 110]) }) > steady, 'the same success, a faster median');
  assert.ok(Math.floor(steady / 100) === 100 && Math.floor(lucky / 100) === 67, 'the whole part is the success %');
});

test('a pass needs passRatio of the samples (two of three by default, at least one): one lucky answer is 0', () => {
  assert.equal(PASS_RATIO, 0.66);
  assert.deepEqual([needOf(3), needOf(2), needOf(5), needOf(1), needOf(3, 1), needOf(4, 0.5)], [2, 2, 4, 1, 3, 2]);
  assert.equal(passes(delayStats([50, -1, -1])), false);
  assert.equal(passes(delayStats([50, 60, -1])), true);
  assert.equal(passes(delayStats([50, -1])), false, 'one of two is not two thirds');
  assert.equal(passes(delayStats([50])), true);
  assert.equal(passes(delayStats([50, -1, -1]), 0.3), true, 'a looser ratio when asked');
  assert.equal(scoreResult({ delay: delayStats([50, -1, -1]) }), 0);
  assert.equal(scoreResult({ delay: delayStats([50, -1, -1]) }, { passRatio: 0.3 }), 3300 + 79);
  assert.equal(scoreResult({ delay: delayStats([-1, -1, -1]), tcp: { ok: true, ms: 5 } }), 0, 'no answer at all, whatever else was measured');
  assert.equal(scoreResult({ delay: { min: 0, avg: 200, jitter: 0, loss: 0, samples: [] } }), 10050, 'a row from before the median existed ranks by its mean');
});

test('a download that was tested and failed scores 0; one that worked leaves the score to the latency', () => {
  assert.equal(scoreResult({ delay: delayStats([50, 50, 50]), down: down(0, false) }), 0);
  assert.equal(scoreResult({ delay: delayStats([50, 50, 50]), down: down(5) }), scoreResult({ delay: delayStats([50, 50, 50]) }));
  assert.equal(scoreResult({ tcp: { ok: true, ms: 30 }, down: down(4, true, 200) }), 10050, 'no delay: the download’s first byte is the latency');
});

test('TCP-only: a connect is a full success ranked by its time; a failed connect, an error and nothing are 0', () => {
  assert.equal(scoreResult({ tcp: { ok: true, ms: 0 } }), 10099);
  assert.equal(scoreResult({ tcp: { ok: true, ms: 200 } }), 10050);
  assert.equal(scoreResult({ tcp: { ok: false, ms: -1, error: 'timeout' } }), 0);
  assert.equal(scoreResult({ tcp: null, delay: null, down: null, up: null }), 0);
  assert.equal(scoreResult(null), 0);
  assert.equal(scoreResult({ error: 'spawn failed' }), 0);
});

test('reasonOf: the probes’ own reason first; unstable for a series that answered too seldom; download-failed; no-tcp', () => {
  assert.equal(reasonOf({ reason: 'core' }), 'core');
  assert.equal(reasonOf({ delay: delayStats([50, -1, -1]) }), 'unstable');
  assert.equal(reasonOf({ delay: Object.assign(delayStats([-1, -1, -1]), { reason: 'wrong-answer' }) }), 'wrong-answer');
  assert.equal(reasonOf({ delay: delayStats([-1, -1, -1]) }), 'timeout');
  assert.equal(reasonOf({ delay: delayStats([50, 60, 70]), down: down(0, false) }), 'download-failed');
  assert.equal(reasonOf({ tcp: { ok: false, ms: -1 } }), 'no-tcp');
  assert.equal(reasonOf({ tcp: { ok: false, skipped: true }, delay: delayStats([50, 50, 50]) }), '');
  assert.equal(reasonOf(null), '');
});
