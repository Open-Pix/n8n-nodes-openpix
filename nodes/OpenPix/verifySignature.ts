import {
  BinaryToTextEncoding,
  createHmac,
  createVerify,
  timingSafeEqual,
} from 'crypto';

// HMAC-SHA1 over the raw body, keyed by the webhook's hmacSecretKey.
// Sent by the webhook service whenever the webhook has an hmacSecretKey.
export const HMAC_SIGNATURE_HEADER = 'x-openpix-signature';

// RSA-SHA256 over the raw body, signed with the platform private key.
// Sent on every webhook, verified against the OpenPix webhook public key.
export const RSA_SIGNATURE_HEADER = 'x-webhook-signature';

const safeEqual = (received: string, expected: string): boolean => {
  const receivedBuffer = Buffer.from(received);
  const expectedBuffer = Buffer.from(expected);

  if (receivedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(receivedBuffer, expectedBuffer);
};

type VerifyHmacSignatureInput = {
  hmacSecretKey: string;
  rawBody: Buffer;
  signature?: string;
};

export const verifyHmacSignature = ({
  hmacSecretKey,
  rawBody,
  signature,
}: VerifyHmacSignatureInput): boolean => {
  if (!signature) {
    return false;
  }

  // The service digests in base64, older integrations may still send hex
  const encodings: BinaryToTextEncoding[] = ['base64', 'hex'];

  return encodings.some((encoding) =>
    safeEqual(
      signature,
      createHmac('sha1', hmacSecretKey).update(rawBody).digest(encoding),
    ),
  );
};

// The public key is distributed base64 encoded, but accept a raw PEM too
const normalizePublicKey = (publicKey: string): string => {
  const trimmed = publicKey.trim();

  if (trimmed.includes('-----BEGIN')) {
    return trimmed;
  }

  return Buffer.from(trimmed, 'base64').toString('utf-8');
};

type VerifyRsaSignatureInput = {
  publicKey: string;
  rawBody: Buffer;
  signature?: string;
};

export const verifyRsaSignature = ({
  publicKey,
  rawBody,
  signature,
}: VerifyRsaSignatureInput): boolean => {
  if (!signature) {
    return false;
  }

  try {
    const verify = createVerify('sha256');

    verify.update(rawBody);
    verify.end();

    return verify.verify(normalizePublicKey(publicKey), signature, 'base64');
  } catch (error) {
    // A malformed key must not let an unverified payload through
    return false;
  }
};
