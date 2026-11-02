#!/usr/bin/env node
'use strict';
/**
 * The lists the app ships (src/main/scan/cdnRanges.data.json), fetched from each
 * CDN's own public list. Run by hand before a release; the page's Update button
 * does the same at run time for whoever has the app. Cloudflare's list lives in
 * targets.js: this says when it has moved.
 */
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'src', 'main', 'scan', 'cdnRanges.data.json');
const SHIPPED = ['fastly', 'cloudfront', 'gcore'];

async function main() {
  // the data file must exist for targets.js to load; a first run writes it empty
  if (!fs.existsSync(DATA)) fs.writeFileSync(DATA, JSON.stringify({ fetchedAt: '', fastly: [], cloudfront: [], gcore: [] }));
  const C = require('../src/main/scan/cdnRanges');
  const T = require('../src/main/scan/targets');

  const out = { fetchedAt: new Date().toISOString().slice(0, 10) };
  for (const id of SHIPPED) {
    out[id] = await C.fetchList(id);
    console.log(`${id}: ${out[id].length} ranges`);
  }
  fs.writeFileSync(DATA, JSON.stringify(out, null, 1) + '\n');

  const cf = await C.fetchList('cf');
  const known = new Set(T.PRESETS.cf.ranges);
  const moved = cf.length !== known.size || cf.some((r) => !known.has(r));
  console.log(moved ? `cf: the list moved — update CF_IPV4_RANGES / CF_IPV6_RANGES in targets.js:\n${cf.join('\n')}` : `cf: ${cf.length} ranges, as in targets.js`);
}

main().catch((e) => { console.error(e && e.message ? e.message : e); process.exit(1); });
