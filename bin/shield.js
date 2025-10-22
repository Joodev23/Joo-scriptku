#!/usr/bin/env node
const {protect, activateSelfShield} = require('../lib/shield');
const target = process.argv[2]||process.cwd();

activateSelfShield();           
protect(require('path').resolve(target));