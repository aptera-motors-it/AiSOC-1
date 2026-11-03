#!/usr/bin/env node
'use strict';

/**
 * Exercise minimatch consumers that break when registry minimatch@11 is required
 * without a glob@7-compatible Minimatch.set (serve-handler, eslint-plugin-react,
 * glob.sync wildcards, rimraf glob patterns).
 *
 * Usage: node scripts/check_minimatch_call_sites.js [--modules-dir PATH]
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { Writable } = require('stream');

const repoRoot = path.join(__dirname, '..');

const defaultModulePaths = {
  glob: path.join(repoRoot, 'node_modules/.pnpm/glob@7.2.3/node_modules'),
  rimraf: path.join(repoRoot, 'node_modules/.pnpm/rimraf@3.0.2/node_modules'),
  serveHandler: path.join(repoRoot, 'node_modules/.pnpm/serve-handler@6.1.7/node_modules'),
  eslintReact: path.join(
    repoRoot,
    'node_modules/.pnpm',
    ...(() => {
      const base = path.join(repoRoot, 'node_modules/.pnpm');
      const { readdirSync } = fs;
      const name = readdirSync(base).find((entry) => entry.startsWith('eslint-plugin-react@'));
      if (!name) {
        throw new Error('eslint-plugin-react is not installed');
      }
      return [name, 'node_modules'];
    })(),
  ),
  eslintImport: path.join(
    repoRoot,
    'node_modules/.pnpm',
    ...(() => {
      const base = path.join(repoRoot, 'node_modules/.pnpm');
      const { readdirSync } = fs;
      const name = readdirSync(base).find((entry) => entry.startsWith('eslint-plugin-import@'));
      if (!name) {
        throw new Error('eslint-plugin-import is not installed');
      }
      return [name, 'node_modules'];
    })(),
  ),
};

const modulesDir = (() => {
  const idx = process.argv.indexOf('--modules-dir');
  if (idx !== -1 && process.argv[idx + 1]) {
    return path.resolve(process.argv[idx + 1]);
  }
  return null;
})();

function resolveFrom(name, searchPaths) {
  const paths = searchPaths || (modulesDir ? [modulesDir] : [repoRoot, path.join(repoRoot, 'node_modules')]);
  return require(require.resolve(name, { paths }));
}

function assert(condition, message) {
  if (!condition) {
    console.error(`check_minimatch_call_sites: ${message}`);
    process.exit(1);
  }
}

function checkGlobSyncWildcards() {
  const glob = resolveFrom('glob', [defaultModulePaths.glob]);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aisoc-glob-'));
  fs.writeFileSync(path.join(tmp, 'a.json'), '{}');
  fs.writeFileSync(path.join(tmp, 'b.txt'), 'x');
  const scripts = path.join(tmp, 'scripts');
  fs.mkdirSync(scripts);
  fs.writeFileSync(path.join(scripts, 'run.py'), 'print(1)\n');
  const absDir = path.join(tmp, 'absdir');
  fs.mkdirSync(absDir);
  fs.writeFileSync(path.join(absDir, 'tool.py'), 'pass\n');
  const patterns = ['*.json', 'scripts/*.py', path.join(absDir, '*.py').replace(/\\/g, '/')];
  for (const pattern of patterns) {
    let hits;
    try {
      hits = glob.sync(pattern, { cwd: tmp, absolute: path.isAbsolute(pattern) });
    } catch (err) {
      throw new Error(`glob.sync(${JSON.stringify(pattern)}) threw: ${err.message}`);
    }
    assert(Array.isArray(hits) && hits.length >= 1, `glob.sync(${JSON.stringify(pattern)}) returned no matches`);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

function checkRimrafWithGlobPattern() {
  const rimraf = resolveFrom('rimraf', [defaultModulePaths.rimraf, defaultModulePaths.glob]);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aisoc-rimraf-glob-'));
  fs.writeFileSync(path.join(tmp, 'keep.json'), '{}');
  fs.writeFileSync(path.join(tmp, 'drop.txt'), 'x');
  const pattern = path.join(tmp, '*.txt').replace(/\\/g, '/');
  return new Promise((resolve, reject) => {
    rimraf(pattern, (err) => {
      if (err) {
        reject(err);
        return;
      }
      try {
        assert(fs.existsSync(path.join(tmp, 'keep.json')), 'rimraf glob removed non-matching file');
        assert(!fs.existsSync(path.join(tmp, 'drop.txt')), 'rimraf glob failed to remove match');
        fs.rmSync(tmp, { recursive: true, force: true });
        resolve();
      } catch (assertErr) {
        reject(assertErr);
      }
    });
  });
}

async function checkServeHandlerHeaders() {
  const handler = resolveFrom('serve-handler', [defaultModulePaths.serveHandler]);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aisoc-serve-'));
  fs.writeFileSync(path.join(tmp, 'index.html'), '<html></html>');
  const captured = {};
  const request = { url: '/index.html', headers: { accept: 'text/html' } };
  const response = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  response.statusCode = 200;
  response.setHeader = (name, value) => {
    captured[name.toLowerCase()] = value;
  };
  response.writeHead = (code, headers) => {
    response.statusCode = code;
    if (headers) {
      Object.entries(headers).forEach(([key, value]) => {
        captured[key.toLowerCase()] = value;
      });
    }
  };
  response.end = () => {};
  await handler(request, response, {
    public: tmp,
    cleanUrls: false,
    headers: [{ source: '**/*.html', headers: [{ key: 'X-Probe', value: 'matched' }] }],
  });
  assert(captured['x-probe'] === 'matched', 'serve-handler headers glob did not match **/*.html');
  await new Promise((resolve) => {
    response.on('finish', resolve);
    if (response.writableFinished) {
      resolve();
    }
  });
  fs.rmSync(tmp, { recursive: true, force: true });
}

function checkEslintReactNoDangerRule() {
  const eslintPaths = [defaultModulePaths.eslintReact, defaultModulePaths.glob];
  const { RuleTester } = resolveFrom('eslint', eslintPaths);
  const rule = resolveFrom('eslint-plugin-react/lib/rules/no-danger', eslintPaths);
  const ruleTester = new RuleTester({
    languageOptions: {
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
  });
  ruleTester.run('no-danger-customComponentNames', rule, {
    valid: [{ code: '<Bar />', options: [{ customComponentNames: ['Foo*'] }] }],
    invalid: [
      {
        code: '<FooBar dangerouslySetInnerHTML={{ __html: "x" }} />',
        options: [{ customComponentNames: ['Foo*'] }],
        errors: [{ messageId: 'dangerousProp' }],
      },
    ],
  });
}

function checkEslintImportNoInternalModulesMakeRe() {
  const importPaths = [defaultModulePaths.eslintImport, defaultModulePaths.glob];
  const minimatch = resolveFrom('minimatch', importPaths);
  assert(typeof minimatch.makeRe === 'function', 'minimatch.makeRe must be a function');
  const re = minimatch.makeRe('packages/**/internal/**');
  assert(typeof re.test === 'function', 'makeRe result must provide test()');
  assert(re.test('packages/foo/internal/bar'), 'makeRe pattern should match import paths');
  const rule = resolveFrom('eslint-plugin-import/lib/rules/no-internal-modules', importPaths);
  rule.create({ options: [{ allow: ['packages/**/public/**'] }] });
}

async function main() {
  checkGlobSyncWildcards();
  await checkRimrafWithGlobPattern();
  await checkServeHandlerHeaders();
  checkEslintReactNoDangerRule();
  checkEslintImportNoInternalModulesMakeRe();
  console.log('check_minimatch_call_sites: OK');
}

main().catch((err) => {
  console.error(`check_minimatch_call_sites: ${err.message}`);
  process.exit(1);
});
