const test = require('node:test');
const assert = require('node:assert/strict');
const Passgen = require('../js/passgen.js');

const classes = (value) => ({
  lower: /[a-z]/.test(value),
  upper: /[A-Z]/.test(value),
  digit: /\d/.test(value),
  symbol: /[^a-zA-Z0-9]/.test(value),
});

test('sans politique : 20 caractères, les quatre classes', () => {
  for (let i = 0; i < 50; i++) {
    const value = Passgen.generate();
    assert.equal(value.length, 20);
    assert.deepEqual(classes(value), { lower: true, upper: true, digit: true, symbol: true });
  }
});

test('passwordrules : longueurs, classes, symboles permis, répétitions', () => {
  const policy = Passgen.fromPasswordRules('minlength: 8; maxlength: 12; required: lower; required: upper; required: digit; required: [-!]; max-consecutive: 2');
  assert.deepEqual(policy, { minLength: 8, maxLength: 12, maxConsecutive: 2, required: ['lower', 'upper', 'digit', 'symbol'], symbols: '-!' });
  for (let i = 0; i < 50; i++) {
    const value = Passgen.generate(policy);
    assert.equal(value.length, 12);
    assert.match(value, /^[a-zA-Z0-9!-]+$/);
    assert.match(value, /[-!]/);
    assert.doesNotMatch(value, /(.)\1\1/);
  }
  // Classes citées sans symbole : aucun symbole.
  const alnum = Passgen.fromPasswordRules('required: lower, upper; required: digit; minlength: 10');
  assert.equal(alnum.symbols, '');
  assert.match(Passgen.generate(alnum), /^[a-zA-Z0-9]{20}$/);
});

test('attributs HTML : maxlength et pattern respectés', () => {
  const policy = Passgen.fromAttributes({ minLength: '6', maxLength: '10', pattern: '(?=.*\\d)(?=.*[A-Z])[A-Za-z0-9]{6,10}' });
  for (let i = 0; i < 30; i++) {
    const value = Passgen.generate(policy);
    assert.ok(value.length <= 10);
    assert.match(value, /^(?=.*\d)(?=.*[A-Z])[A-Za-z0-9]{6,10}$/);
  }
  assert.deepEqual(Passgen.fromAttributes({ minLength: -1, maxLength: 524288 }), { maxLength: 524288, required: [] });
  // Longueurs du motif seul : « .{8,12} » sans maxlength.
  const fromPattern = Passgen.fromAttributes({ pattern: '[A-Za-z0-9]{8,12}' });
  assert.deepEqual([fromPattern.minLength, fromPattern.maxLength], [8, 12]);
  assert.match(Passgen.generate(fromPattern), /^[A-Za-z0-9]{12}$/);
});

test('texte d’aide, français et anglais', () => {
  assert.deepEqual(Passgen.fromText('Votre mot de passe doit contenir entre 8 et 16 caractères, dont une majuscule et un chiffre.'),
    { minLength: 8, maxLength: 16, required: ['upper', 'digit'] });
  assert.deepEqual(Passgen.fromText('12 caractères minimum, au moins un caractère spécial parmi : ! @ # $'),
    { minLength: 12, required: ['symbol'], symbols: '!@#$' });
  assert.deepEqual(Passgen.fromText('Password must be at least 10 characters and no more than 32 characters. Letters and numbers only.'),
    { minLength: 10, maxLength: 32, required: ['digit'], symbols: '' });
  assert.deepEqual(Passgen.fromText('Use 8 or more characters with a mix of letters, numbers & symbols'),
    { minLength: 8, required: ['digit', 'symbol'] });
  assert.deepEqual(Passgen.fromText('Bienvenue !'), { required: [] });
});

test('fusion : la source la plus sûre l’emporte, les classes s’additionnent', () => {
  const merged = Passgen.merge(
    Passgen.fromPasswordRules('maxlength: 16'),
    Passgen.fromAttributes({ maxLength: 30, minLength: 8 }),
    Passgen.fromText('pas de caractères spéciaux, une majuscule')
  );
  assert.deepEqual(merged, { required: ['upper'], maxLength: 16, minLength: 8, symbols: '' });
  assert.equal(Passgen.generate(merged).length, 16);
  assert.deepEqual(Passgen.describe(merged), { length: 16, min: 8, max: 16, symbols: '', classes: ['lower', 'upper', 'digit'], detected: true });
  assert.equal(Passgen.describe(Passgen.merge()).detected, false);
});
