#!/usr/bin/env node
'use strict';

/**
 * Exercise minimatch consumers that break when registry minimatch@11 is required
 * as a bare function (serve-handler, eslint-plugin-react) or via glob@7 (sync).
 *
 * Usage: node scripts/check_minimatch_call_sites.js [--modules-dir PATH]
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const modulesDir = (() => {
  const idx = process.argv.indexOf('--modules-dir');
  if (idx !== -1 && process.argv[idx + 1]) {
    return path.resolve(process.argv[idx + 1]);
  }
  return path.join(__dirname, '..', 'node_modules');
})();

function resolveFrom(name) {
  return require(require.resolve(name, { paths: [modulesDir] }));
}

function assert(condition, message) {
  if (!condition) {
    console.error(`check_minimatch_call_sites: ${message}`);
    process.exit(1);
  }
}

function checkGlobSync() {
  const glob = resolveFrom('glob');
  assert(typeof glob.sync === 'function', 'glob.sync missing');
  const globRoot = path.dirname(require.resolve('glob/package.json', { paths: [modulesDir] }));
  const hits = glob.sync('package.json', { cwd: globRoot });
  assert(Array.isArray(hits) && hits.length >= 1, 'glob.sync returned no matches');
}

function checkRimrafWithGlob() {
  const rimraf = resolveFrom('rimraf');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aisoc-rimraf-'));
  fs.writeFileSync(path.join(tmp, 'x'), 'x');
  return new Promise((resolve, reject) => {
    rimraf(tmp, (err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
}

function checkServeHandlerHeaders() {
  const slasher = resolveFrom('serve-handler/src/glob-slash');
  const minimatch = resolveFrom('minimatch');
  assert(typeof minimatch === 'function', 'minimatch must be callable for serve-handler');
  const source = '/static/**';
  const requestPath = '/static/app.js';
  const slashed = slasher(source);
  assert(minimatch(path.posix.resolve(requestPath), slashed), 'serve-handler style minimatch match failed');
}

function checkEslintReactNoDanger() {
  const minimatch = resolveFrom('minimatch');
  assert(typeof minimatch === 'function', 'minimatch must be callable for eslint-plugin-react');
  const customComponentNames = ['Foo*'];
  const functionName = 'FooBar';
  assert(
    customComponentNames.some((name) => minimatch(functionName, name)),
    'eslint-plugin-react customComponentNames match failed',
  );
}

async function main() {
  checkGlobSync();
  await checkRimrafWithGlob();
  checkServeHandlerHeaders();
  checkEslintReactNoDanger();
  console.log('check_minimatch_call_sites: OK');
}

main().catch((err) => {
  console.error(`check_minimatch_call_sites: ${err.message}`);
  process.exit(1);
});
