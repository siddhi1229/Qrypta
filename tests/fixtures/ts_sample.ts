// Sample TypeScript file containing deliberate cryptographic usages for testing

import * as crypto from 'crypto';
import { SignJWT } from 'jose';

export async function generateWebCryptoKeys(): Promise<void> {
  const rsaKey = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );

  const ecdsaKey = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  const aesKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function createJoseToken(secret: Uint8Array): Promise<string> {
  const jwt = await new SignJWT({ 'urn:example:claim': true })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(secret);

  return jwt;
}

export function hashingAndTls() {
  const hash = crypto.createHash('sha384').update('data').digest('hex');
  const tlsOptions = {
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  };
  return { hash, tlsOptions };
}
