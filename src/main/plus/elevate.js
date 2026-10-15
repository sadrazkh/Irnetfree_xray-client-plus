'use strict';
/**
 * plus: one administrator command on demand. Plus v3 runs without
 * administrator rights (nothing it does needs them); the Server tab's Windows
 * firewall rule does, so that one `netsh` asks for elevation itself: tried as
 * is first (an elevated session just runs it), and when Windows answers that
 * it needs elevation, run again through PowerShell's Start-Process -Verb RunAs
 * — the UAC prompt — waiting for its exit code. A declined prompt is an error
 * the tab shows, never a hang.
 */
const { execFile: nodeExecFile } = require('child_process');

const TIMEOUT_MS = 10000;
const ELEVATED_TIMEOUT_MS = 120000;   // the user reads the UAC prompt
const NEEDS_ELEVATION = /requires elevation|run as administrator|access is denied|0x80070005/i;

/** A PowerShell single-quoted literal. */
const psQuote = (s) => "'" + String(s).replace(/'/g, "''") + "'";

/** The PowerShell command that runs `bin args…` elevated and exits with its exit code. */
function elevatedCommand(bin, args) {
  const list = (args || []).map(psQuote).join(',');
  return `$p = Start-Process -FilePath ${psQuote(bin)} -ArgumentList @(${list}) -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode`;
}

/**
 * createRunAdmin({ platform, execFile }) → (bin, args) => Promise<{ err, stdout, stderr, elevated }>
 * Never throws; `err` is set on failure, as the tab's own runner does.
 */
function createRunAdmin({ platform = process.platform, execFile = nodeExecFile } = {}) {
  const run = (bin, args, timeout) => new Promise((resolve) => {
    try {
      execFile(bin, args, { windowsHide: true, timeout }, (err, stdout, stderr) => {
        resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') });
      });
    } catch (e) { resolve({ err: e, stdout: '', stderr: '' }); }
  });
  return async (bin, args) => {
    const first = await run(bin, args, TIMEOUT_MS);
    if (!first.err || platform !== 'win32') return Object.assign(first, { elevated: false });
    if (!NEEDS_ELEVATION.test(first.stdout + '\n' + first.stderr + '\n' + (first.err.message || ''))) return Object.assign(first, { elevated: false });
    const r = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', elevatedCommand(bin, args)], ELEVATED_TIMEOUT_MS);
    if (r.err && /canceled by the user|cancelled by the user|operation was canceled/i.test(r.stdout + r.stderr)) {
      r.err = new Error('the administrator prompt was declined');
      r.stderr = 'the administrator prompt was declined';
    }
    return Object.assign(r, { elevated: true });
  };
}

module.exports = { createRunAdmin, elevatedCommand, psQuote, NEEDS_ELEVATION };
