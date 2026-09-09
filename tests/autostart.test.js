'use strict';
/**
 * Start with the OS. On Windows this is a scheduled task, because the app
 * requires elevation and UAC silently skips Run-key entries for such programs.
 * The arguments are what the OS gets; they are pinned here because nothing
 * else can run schtasks safely in a test.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, autostartExe, TASK } = require('../src/main/autostart');

const INSTALLED = 'C:\\Program Files\\IRNetFree Plus\\IRNetFree Plus.exe';

test('the logon task runs the exe hidden with highest privileges, replacing any older task', () => {
  assert.deepEqual(schtasksCreateArgs(INSTALLED), [
    '/Create', '/TN', 'IRNetFreePlus', '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/IT', '/F',
    '/TR', '"' + INSTALLED + '" --hidden'
  ]);
  assert.deepEqual(schtasksDeleteArgs(), ['/Delete', '/TN', 'IRNetFreePlus', '/F']);
  assert.deepEqual(schtasksQueryArgs(), ['/Query', '/TN', 'IRNetFreePlus']);
  // plus: a fixed name, and NOT the original's 'IRNetFree' — the two apps
  // install side by side and must each keep their own logon task.
  assert.equal(TASK, 'IRNetFreePlus', 'a fixed name: a reinstall replaces the task instead of adding one');
  assert.notEqual(TASK, 'IRNetFree', 'the original IRNetFree owns that task name');
});

test('the portable build names its real file; the installed build is its own exe', () => {
  const portable = 'D:\\apps\\IRNetFree-Plus-Portable.exe';
  assert.equal(autostartExe({ PORTABLE_EXECUTABLE_FILE: portable }, 'C:\\Temp\\extracted\\IRNetFree Plus.exe'), portable);
  assert.equal(autostartExe({}, INSTALLED), INSTALLED);
});
