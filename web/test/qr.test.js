// Aller-retour QR : génère un QR otpauth (comme un service le ferait) et le décode avec le jsQR vendorisé.
const test = require('node:test');
const assert = require('node:assert/strict');
const QRCode = require('qrcode');
const jsQR = require('../vendor/jsQR.js');
const OTP = require('../js/otp.js');

function rasterize(text, { moduleSize = 6, margin = 4 } = {}) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size;
  const size = (n + margin * 2) * moduleSize;
  const data = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (!qr.modules.get(y, x)) continue;
      for (let dy = 0; dy < moduleSize; dy++) {
        for (let dx = 0; dx < moduleSize; dx++) {
          const px = ((y + margin) * moduleSize + dy) * size + (x + margin) * moduleSize + dx;
          data[px * 4] = data[px * 4 + 1] = data[px * 4 + 2] = 0;
        }
      }
    }
  }
  return { data, size };
}

test('QR otpauth généré → décodé → parsé', () => {
  const uri = 'otpauth://totp/Proton:jacques%40hullu.fr?secret=JBSWY3DPEHPK3PXP&issuer=Proton';
  const { data, size } = rasterize(uri);
  const result = jsQR(data, size, size, { inversionAttempts: 'attemptBoth' });
  assert.ok(result, 'QR non détecté');
  assert.equal(result.data, uri);
  const parsed = OTP.parseOtpauthUri(result.data);
  assert.equal(parsed.issuer, 'Proton');
  assert.equal(parsed.account, 'jacques@hullu.fr');
});
