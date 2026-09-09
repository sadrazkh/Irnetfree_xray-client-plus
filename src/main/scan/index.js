'use strict';
/**
 * plus: the IP-scan tab — a config tested through many addresses on every
 * installed xray-format core (spec section 3). Replaced by the real module in
 * task C1; this stub keeps both mirrors bootable until then.
 */
function createScan(ctx) {
  return { register() {}, stop: async () => {}, busy: () => false };
}

module.exports = { createScan };
