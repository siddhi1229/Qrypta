// Sample JavaScript file containing deliberate cryptographic usages for testing

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const tls = require('tls');
const https = require('https');
const CryptoJS = require('crypto-js');

function runHashes(data) {
  const h1 = crypto.createHash('sha256').update(data).digest('hex');
  const h2 = crypto.createHash('md5').update(data).digest('hex');
  const h3 = CryptoJS.SHA512('sample string');
  return { h1, h2, h3 };
}

function runAsymmetric() {
  const rsaPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const edPair = crypto.generateKeyPairSync('ed25519');
  const dh = crypto.createDiffieHellman(2048);
  const ecdh = crypto.createECDH('prime256v1');
  return { rsaPair, edPair, dh, ecdh };
}

function runSymmetric(key, iv, nonce) {
  const c1 = crypto.createCipheriv('aes-256-gcm', key, iv);
  const c2 = crypto.createCipheriv('chacha20-poly1305', key, nonce);
  const c3 = crypto.createCipheriv('des-ede3-cbc', key, iv);
  const c4 = CryptoJS.DES.encrypt('test', 'secret');
  return { c1, c2, c3, c4 };
}

function runTokens(payload, secret) {
  const token1 = jwt.sign(payload, secret, { algorithm: 'RS256' });
  const token2 = jwt.sign(payload, secret, { algorithm: 'HS384' });
  jwt.verify(token1, secret, { algorithms: ['ES256'] });
  return { token1, token2 };
}

function runTls() {
  const server1 = tls.createServer({
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3'
  });

  const server2 = https.createServer({
    secureProtocol: 'TLSv1_2_method'
  });

  return { server1, server2 };
}

module.exports = { runHashes, runAsymmetric, runSymmetric, runTokens, runTls };
