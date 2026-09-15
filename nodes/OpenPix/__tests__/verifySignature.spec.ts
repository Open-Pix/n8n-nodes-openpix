import { createHmac, generateKeyPairSync, createSign } from 'crypto';

import { verifyHmacSignature, verifyRsaSignature } from '../verifySignature';

const hmacSecretKey = 'openpix_g98Nj/oCocUi4mBu/AP5avmbLEmk=';

// Exactly the bytes the webhook service signs and sends
const payload = JSON.stringify({
  event: 'OPENPIX:CHARGE_COMPLETED',
  charge: {
    status: 'COMPLETED',
    value: 10000,
    correlationID: 'abc-123',
  },
});

const rawBody = Buffer.from(payload);

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const signWithRsa = (body: string, key = privateKey) => {
  const sign = createSign('sha256');

  sign.update(Buffer.from(body));
  sign.end();

  return sign.sign(key, 'base64');
};

describe('verifyHmacSignature', () => {
  it('should accept a genuine base64 signature', () => {
    const signature = createHmac('sha1', hmacSecretKey)
      .update(rawBody)
      .digest('base64');

    expect(verifyHmacSignature({ hmacSecretKey, rawBody, signature })).toBe(
      true,
    );
  });

  it('should accept a genuine hex signature', () => {
    const signature = createHmac('sha1', hmacSecretKey)
      .update(rawBody)
      .digest('hex');

    expect(verifyHmacSignature({ hmacSecretKey, rawBody, signature })).toBe(
      true,
    );
  });

  it('should reject a tampered body', () => {
    const signature = createHmac('sha1', hmacSecretKey)
      .update(rawBody)
      .digest('base64');

    const tamperedBody = Buffer.from(
      payload.replace('"value":10000', '"value":10000000'),
    );

    expect(
      verifyHmacSignature({
        hmacSecretKey,
        rawBody: tamperedBody,
        signature,
      }),
    ).toBe(false);
  });

  it('should reject a signature made with another key', () => {
    const signature = createHmac('sha1', 'another_secret')
      .update(rawBody)
      .digest('base64');

    expect(verifyHmacSignature({ hmacSecretKey, rawBody, signature })).toBe(
      false,
    );
  });

  it('should reject a missing signature', () => {
    expect(
      verifyHmacSignature({ hmacSecretKey, rawBody, signature: undefined }),
    ).toBe(false);
  });

  it('should reject a garbage signature', () => {
    expect(
      verifyHmacSignature({
        hmacSecretKey,
        rawBody,
        signature: 'not-base64!!',
      }),
    ).toBe(false);
  });

  it('should reject a body that only differs in non-ASCII bytes', () => {
    const signedBody = Buffer.from(
      JSON.stringify({ reason: 'Tempo limite de liquidação' }),
    );
    const signature = createHmac('sha1', hmacSecretKey)
      .update(signedBody)
      .digest('base64');

    expect(
      verifyHmacSignature({
        hmacSecretKey,
        rawBody: Buffer.from(JSON.stringify({ reason: 'Tempo limite' })),
        signature,
      }),
    ).toBe(false);
  });
});

describe('verifyRsaSignature', () => {
  it('should accept a genuine signature with a PEM key', () => {
    expect(
      verifyRsaSignature({
        publicKey,
        rawBody,
        signature: signWithRsa(payload),
      }),
    ).toBe(true);
  });

  it('should accept a genuine signature with a base64 encoded key', () => {
    expect(
      verifyRsaSignature({
        publicKey: Buffer.from(publicKey).toString('base64'),
        rawBody,
        signature: signWithRsa(payload),
      }),
    ).toBe(true);
  });

  it('should reject a tampered body', () => {
    expect(
      verifyRsaSignature({
        publicKey,
        rawBody: Buffer.from(payload.replace('10000', '10000000')),
        signature: signWithRsa(payload),
      }),
    ).toBe(false);
  });

  it('should reject a signature made with another key', () => {
    const other = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    expect(
      verifyRsaSignature({
        publicKey,
        rawBody,
        signature: signWithRsa(payload, other.privateKey),
      }),
    ).toBe(false);
  });

  it('should reject a missing signature', () => {
    expect(
      verifyRsaSignature({ publicKey, rawBody, signature: undefined }),
    ).toBe(false);
  });

  it('should fail closed on a malformed public key', () => {
    expect(
      verifyRsaSignature({
        publicKey: 'not-a-key',
        rawBody,
        signature: signWithRsa(payload),
      }),
    ).toBe(false);
  });
});
