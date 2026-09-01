import crypto from 'node:crypto';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  return bits.match(/.{1,5}/g).map((part) => alphabet[Number.parseInt(part.padEnd(5, '0'), 2)]).join('');
}

function base32Decode(value) {
  const bits = value.toUpperCase().replace(/=+$/, '').split('').map((character) => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('');
  return Buffer.from((bits.match(/.{8}/g) ?? []).map((part) => Number.parseInt(part, 2)));
}

function tokenAt(secret, counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const number = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(number).padStart(6, '0');
}

export function createTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

export function verifyTotp(secret, token, now = Date.now()) {
  const counter = Math.floor(now / 30_000);
  return [-1, 0, 1].some((window) => {
    const expected = tokenAt(secret, counter + window);
    const received = String(token ?? '').padStart(6, '0');
    return expected.length === received.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
  });
}

export function totpUri(secret, email) {
  return `otpauth://totp/CiberGuate:${encodeURIComponent(email)}?secret=${secret}&issuer=CiberGuate&algorithm=SHA1&digits=6&period=30`;
}

