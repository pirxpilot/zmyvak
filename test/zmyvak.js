import test from 'node:test';
import zmyvak from '../lib/zmyvak.js';

test.todo('zmyvak must have at least one test', t => {
  zmyvak();
  t.assert.fail('Need to write tests.');
});
