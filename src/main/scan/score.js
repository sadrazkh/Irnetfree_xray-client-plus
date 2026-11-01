'use strict';
/**
 * plus: ranking a scan result. Pure.
 *
 * 2026-11-01, the owner: "the score ranks by success ratio, then median
 * latency, then jitter". So a target that answered every time beats one that
 * answered two times of three, however fast the second was, and among the
 * ones that answered as often the faster wins:
 *
 *   score  = 100 × success% + latency points
 *   success% = round(100 × answered / asked), the delay series' samples
 *   latency points = round(99 / (1 + median / 200))   — 99 at 0 ms, 50 at
 *                    about 200 ms, 33 at 400 ms; never 100, so they never
 *                    reach the next success step
 *   a tie: the lower median, then the lower jitter (byRank in scanner.js)
 *
 * The page shows score / 100: the whole part is the success %, the decimals
 * the speed of the answers ("100.62"). A row that does not PASS scores 0 —
 * passing is answering at least passRatio of the samples (two of three by
 * default; at least one), so one lucky answer out of three is not a pass.
 * A download that was tested and failed scores 0 as well: a tunnel that
 * cannot carry the speed test must not outrank one that did. The download's
 * Mbps is not in the score — sort the Download column to rank by it (and
 * "copy the best" follows the table's order). A scan with only the TCP test
 * ticked has no tunnel data: it ranks by connect time, as a full success.
 *
 * v3.0's score (base × (1 − loss) / (1 + median/200) / (1 + jitter/100),
 * base = 100 × Mbps after a download) let a fast target with a third of its
 * samples lost outrank a slower one that never lost any.
 */

const round1 = (v) => Math.round(v * 10) / 10;
/** The pass ratio when nobody said: two of three. */
const PASS_RATIO = 0.66;

/**
 * delayStats(samplesMs) → { min, median, avg, jitter, loss, samples }
 * A sample of -1 is a failed request. min/median/avg/jitter are over the
 * successes, jitter being their mean absolute deviation; loss is failed / total.
 */
function delayStats(samples) {
  const list = Array.isArray(samples) ? samples.map(Number) : [];
  const ok = list.filter(v => v >= 0);
  if (!list.length || !ok.length) return { min: 0, median: 0, avg: 0, jitter: 0, loss: 1, samples: list };
  const sorted = ok.slice().sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  const median = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  const avg = ok.reduce((s, v) => s + v, 0) / ok.length;
  const jitter = ok.length > 1 ? ok.reduce((s, v) => s + Math.abs(v - avg), 0) / ok.length : 0;
  return {
    min: sorted[0],
    median: round1(median),
    avg: round1(avg),
    jitter: round1(jitter),
    loss: (list.length - ok.length) / list.length,
    samples: list
  };
}

/** How many of n samples a pass needs: passRatio of them, at least one. */
function needOf(n, passRatio) {
  const r = Number(passRatio);
  const ratio = Number.isFinite(r) && r > 0 ? Math.min(1, r) : PASS_RATIO;
  return Math.max(1, Math.min(n, Math.ceil(n * ratio - 1e-9)));
}

/** Did a delay series pass: at least passRatio of its samples answered? */
function passes(delay, passRatio) {
  if (!delay || !Array.isArray(delay.samples) || !delay.samples.length) return !!delay && delay.loss < 1;
  const n = delay.samples.length;
  const ok = delay.samples.filter((v) => Number(v) >= 0).length;
  return ok >= needOf(n, passRatio);
}

/** 99 at 0 ms, 50 at ~200 ms: a latency's share of a score step. */
const latencyPoints = (ms) => Math.round(99 / (1 + Math.max(0, Number(ms) || 0) / 200));

/** scoreResult(result, { passRatio }) → number (integer; the page shows it / 100). */
function scoreResult(r, opts) {
  if (!r || r.error) return 0;
  const passRatio = opts && opts.passRatio;
  const down = r.down;
  if (down && !down.ok) return 0;
  if (r.delay) {
    if (!passes(r.delay, passRatio)) return 0;
    // a row from before the median existed still ranks by its mean
    const latency = Number.isFinite(r.delay.median) ? r.delay.median : (r.delay.avg || 0);
    return 100 * Math.round(100 * (1 - (Number(r.delay.loss) || 0))) + latencyPoints(latency);
  }
  if (down) return 100 * 100 + latencyPoints(down.ttfb >= 0 ? down.ttfb : 0);
  if (r.tcp && r.tcp.ok) return 100 * 100 + latencyPoints(r.tcp.ms);
  return 0;
}

/**
 * The reason a row without a pass carries, when the probes did not name a
 * sharper one: 'unstable' for a delay series that answered, only not often
 * enough; else the series' own first failure.
 */
function reasonOf(r, opts) {
  if (!r) return '';
  if (r.reason) return r.reason;
  if (r.down && !r.down.ok) return 'download-failed';
  if (r.delay && !passes(r.delay, opts && opts.passRatio)) {
    const answered = Array.isArray(r.delay.samples) && r.delay.samples.some((v) => Number(v) >= 0);
    return answered ? 'unstable' : (r.delay.reason || 'timeout');
  }
  if (r.tcp && !r.tcp.ok && !r.tcp.skipped) return 'no-tcp';
  return '';
}

module.exports = { scoreResult, delayStats, passes, needOf, reasonOf, latencyPoints, PASS_RATIO };
