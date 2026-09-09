'use strict';
/**
 * plus: ranking a scan result. Pure.
 *
 *   score = base × (1 − loss) / (1 + avg/200) / (1 + jitter/100)
 *   base  = 100 × download Mbps when a download was tested, else 1000
 *
 * Higher is better. A tunnel that never answered a delay probe scores 0, and
 * so does a download that was tested and failed — it must not outrank a slow
 * one that worked. A scan with only the TCP test ticked has no tunnel data,
 * so it ranks by connect time alone: 1000 / (1 + ms/50).
 */

const round1 = (v) => Math.round(v * 10) / 10;

/**
 * delayStats(samplesMs) → { min, avg, jitter, loss, samples }
 * A sample of -1 is a failed request. min/avg/jitter are over the successes,
 * jitter being their mean absolute deviation; loss is failed / total.
 */
function delayStats(samples) {
  const list = Array.isArray(samples) ? samples.map(Number) : [];
  const ok = list.filter(v => v >= 0);
  if (!list.length || !ok.length) return { min: 0, avg: 0, jitter: 0, loss: 1, samples: list };
  const avg = ok.reduce((s, v) => s + v, 0) / ok.length;
  const jitter = ok.length > 1 ? ok.reduce((s, v) => s + Math.abs(v - avg), 0) / ok.length : 0;
  return {
    min: Math.min(...ok),
    avg: round1(avg),
    jitter: round1(jitter),
    loss: (list.length - ok.length) / list.length,
    samples: list
  };
}

/** scoreResult(result) → number, one decimal. */
function scoreResult(r) {
  if (!r) return 0;
  const down = r.down;
  const downBase = () => (down.ok ? 100 * (Number(down.mbps) || 0) : 0);
  if (r.delay) {
    const { avg = 0, jitter = 0, loss = 0 } = r.delay;
    if (loss >= 1) return 0;
    const base = down ? downBase() : 1000;
    return round1(base * (1 - loss) / (1 + avg / 200) / (1 + jitter / 100));
  }
  if (down) return round1(downBase());
  if (r.tcp && r.tcp.ok) return round1(1000 / (1 + Math.max(0, Number(r.tcp.ms) || 0) / 50));
  return 0;
}

module.exports = { scoreResult, delayStats };
