#!/usr/bin/env node
const {protect, JooModss} = require('../lib/shield');
const target = process.argv[2]||process.cwd();

JooModss();           
protect(require('path').resolve(target));