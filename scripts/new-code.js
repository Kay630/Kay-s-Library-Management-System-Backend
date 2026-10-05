// Prints a fresh random admin access code, e.g. LIB-7KQ2-M9XD-4TPA-HW6C
// Usage: npm run new-code   (then paste it into .env as ADMIN_CODE=...)
const crypto = require('node:crypto');
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1 so it is easy to read out loud
const group = () => Array.from(crypto.randomBytes(4), b => ALPHABET[b & 31]).join('');
console.log('LIB-' + [group(), group(), group(), group()].join('-'));
