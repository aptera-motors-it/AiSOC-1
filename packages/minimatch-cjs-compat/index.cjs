'use strict';

const { createRequire } = require('module');

const requireNative = createRequire(__filename);
const impl = requireNative('minimatch-native');

function minimatch(path, pattern, options) {
  return impl.minimatch(path, pattern, options);
}

Object.assign(minimatch, impl);
minimatch.minimatch = impl.minimatch;
minimatch.Minimatch = impl.Minimatch;
minimatch.default = minimatch;

module.exports = minimatch;
