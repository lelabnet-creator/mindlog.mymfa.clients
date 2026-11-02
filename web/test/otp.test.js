const test = require('node:test');
const assert = require('node:assert/strict');
const OTP = require('../js/otp.js');
const { base32Encode } = require('./helpers.js');

const SEEDS = {
  SHA1: base32Encode('12345678901234567890'),
  SHA256: base32Encode('12345678901234567890123456789012'),
  SHA512: base32Encode('1234567890123456789012345678901234567890123456789012345678901234'),
};

// RFC 6238, annexe B (8 chiffres, période 30 s)
const RFC6238 = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

test('TOTP — vecteurs RFC 6238 (SHA1/SHA256/SHA512)', async () => {
  for (const [seconds, sha1, sha256, sha512] of RFC6238) {
    for (const [algorithm, expected] of [['SHA1', sha1], ['SHA256', sha256], ['SHA512', sha512]]) {
      const code = await OTP.totp(SEEDS[algorithm], { digits: 8, algorithm, timestamp: seconds * 1000 });
      assert.equal(code, expected, `${algorithm} @ ${seconds}`);
    }
  }
});

test('HOTP — vecteurs RFC 4226', async () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  for (let counter = 0; counter < expected.length; counter++) {
    assert.equal(await OTP.hotp(SEEDS.SHA1, counter), expected[counter]);
  }
});

test('base32 — tolère espaces, minuscules, tirets et padding', () => {
  const ref = OTP.base32Decode('JBSWY3DPEHPK3PXP');
  assert.deepEqual(OTP.base32Decode('jbsw y3dp-ehpk 3pxp=='), ref);
  assert.equal(Buffer.from(ref.slice(0, 6)).toString(), 'Hello!');
});

test('base32 — erreurs codées', () => {
  assert.throws(() => OTP.base32Decode(''), { code: 'secretEmpty' });
  assert.throws(() => OTP.base32Decode('ABC1'), { code: 'secretInvalidChar', params: { char: '1' } });
  assert.throws(() => OTP.base32Decode('A'), { code: 'secretTooShort' });
  assert.equal(OTP.isValidSecret('JBSWY3DPEHPK3PXP'), true);
  assert.equal(OTP.isValidSecret('not valid!'), false);
});

test('remainingSeconds', () => {
  assert.equal(OTP.remainingSeconds(30, 0), 30);
  assert.equal(OTP.remainingSeconds(30, 29_000), 1);
  assert.equal(OTP.remainingSeconds(30, 30_000), 30);
});

test('parseOtpauthUri — URI complète', () => {
  const p = OTP.parseOtpauthUri('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60');
  assert.deepEqual(p, {
    type: 'totp', issuer: 'ACME Co', account: 'john.doe@email.com',
    secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', algorithm: 'SHA256', digits: 8, period: 60, counter: 0,
  });
});

test('parseOtpauthUri — valeurs par défaut, issuer déduit du label, HOTP', () => {
  const p = OTP.parseOtpauthUri('otpauth://totp/GitHub:me?secret=jbswy3dpehpk3pxp');
  assert.equal(p.issuer, 'GitHub');
  assert.equal(p.account, 'me');
  assert.equal(p.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(p.algorithm, 'SHA1');
  assert.equal(p.digits, 6);
  assert.equal(p.period, 30);
  const h = OTP.parseOtpauthUri('otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=7');
  assert.equal(h.type, 'hotp');
  assert.equal(h.counter, 7);
  assert.equal(h.issuer, '');
});

test('parseOtpauthUri — erreurs codées', () => {
  assert.throws(() => OTP.parseOtpauthUri('nimporte quoi'), { code: 'invalidUri' });
  assert.throws(() => OTP.parseOtpauthUri('https://example.com'), { code: 'notOtpauth' });
  assert.throws(() => OTP.parseOtpauthUri('otpauth://xotp/a?secret=JBSWY3DP'), { code: 'unknownType' });
  assert.throws(() => OTP.parseOtpauthUri('otpauth://totp/a'), { code: 'missingSecret' });
  assert.throws(() => OTP.parseOtpauthUri('otpauth://totp/a?secret=JBSWY3DP&algorithm=MD5'), { code: 'unsupportedAlgorithm' });
  assert.throws(() => OTP.parseOtpauthUri('otpauth://totp/a?secret=JBSWY3DP&digits=4'), { code: 'unsupportedDigits' });
  assert.throws(() => OTP.parseOtpauthUri('otpauth-migration://offline?data=abc'), { code: 'migrationUnsupported' });
});

test('buildOtpauthUri ↔ parseOtpauthUri', () => {
  const account = { type: 'totp', issuer: 'Le Lab', account: 'jacques@le-lab.net', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA512', digits: 8, period: 45 };
  const parsed = OTP.parseOtpauthUri(OTP.buildOtpauthUri(account));
  for (const key of Object.keys(account)) assert.equal(parsed[key], account[key], key);
});
