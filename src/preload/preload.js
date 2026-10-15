'use strict';
/**
 * plus: the page's `window.api` in the Electron window — built from the one
 * map both front ends share (src/main/plus/apiMap.js).
 */
const { contextBridge, ipcRenderer } = require('electron');
const { INVOKE, EVENTS, WINDOW, argOf } = require('../main/plus/apiMap');

const api = { headless: false };
for (const [name, [channel, kind]] of Object.entries(INVOKE)) {
  api[name] = (...args) => ipcRenderer.invoke(channel, argOf(kind, args));
}
for (const [name, channel] of Object.entries(EVENTS)) {
  api[name] = (cb) => { ipcRenderer.on(channel, (e, d) => cb(d)); };
}
for (const [name, channel] of Object.entries(WINDOW)) {
  api[name] = (arg) => ipcRenderer.invoke(channel, arg);
}

contextBridge.exposeInMainWorld('api', api);
