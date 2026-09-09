'use strict';
/**
 * plus: the Server tab — a local Xray server with inbounds, clients and a
 * reverse-proxy role (spec section 2). Replaced by the real module in task S2;
 * this stub keeps both mirrors bootable until then.
 */
function createXServer(ctx) {
  return { register() {}, stop: async () => {}, autoStart() {}, status: () => ({ state: 'stopped' }) };
}

module.exports = { createXServer };
