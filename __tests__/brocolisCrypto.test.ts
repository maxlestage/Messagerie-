//
//  brocolisCrypto.test.ts
//  Vérifie le chiffrement sélectif et la compatibilité de format avec brocolis.
//

import { randomBytes, randomUUID } from 'crypto';

// `expo-crypto` n'existe pas hors application : on le simule avec le module
// `crypto` de Node pour les tests unitaires « purs ».
jest.mock('expo-crypto', () => ({
  getRandomBytes: (n: number) => new Uint8Array(randomBytes(n)),
  randomUUID: () => randomUUID(),
}));

import { base64 } from '@scure/base';
import {
  TOKEN_PREFIX,
  TOKEN_SUFFIX,
  encryptToken,
  decryptTokenBase64,
  encryptMarked,
  decryptTokens,
  generateKeyBase64,
  keyBytesFromBase64,
} from '../src/crypto/brocolisCrypto';

function newKey(): Uint8Array {
  return keyBytesFromBase64(generateKeyBase64());
}

describe('BrocolisCrypto', () => {
  test('clé base64 : aller-retour', () => {
    const b64 = generateKeyBase64();
    expect(keyBytesFromBase64(b64).length).toBe(32);
  });

  test('clé de mauvaise longueur rejetée', () => {
    const short = base64.encode(new Uint8Array(16));
    expect(() => keyBytesFromBase64(short)).toThrow();
  });

  test('clé base64 invalide rejetée', () => {
    expect(() => keyBytesFromBase64('pas du base64 !!!')).toThrow();
  });

  test('jeton : aller-retour', () => {
    const key = newKey();
    const token = encryptToken('hello world', key);
    expect(token.startsWith(TOKEN_PREFIX)).toBe(true);
    expect(token.endsWith(TOKEN_SUFFIX)).toBe(true);

    const inner = token.slice(
      TOKEN_PREFIX.length,
      token.length - TOKEN_SUFFIX.length,
    );
    expect(decryptTokenBase64(inner, key)).toBe('hello world');
  });

  test('chiffrement sélectif : aller-retour', () => {
    const key = newKey();
    const src = 'Coucou ((mon secret)) et ((un autre)) fin';
    const { text: enc, count: n } = encryptMarked(src, key);
    expect(n).toBe(2);
    expect(enc).not.toContain('mon secret');
    expect(enc).toContain(TOKEN_PREFIX);

    const { text: dec, count: m } = decryptTokens(enc, key);
    expect(m).toBe(2);
    expect(dec).toBe('Coucou mon secret et un autre fin');
  });

  test('mauvaise clé : le jeton est conservé', () => {
    const k1 = newKey();
    const k2 = newKey();
    const { text: enc } = encryptMarked('x ((s)) y', k1);
    const { text: dec, count: m } = decryptTokens(enc, k2);
    expect(m).toBe(0);
    expect(dec).toBe(enc); // jeton intact, pas de crash
  });

  test('marqueur non fermé : aucun changement', () => {
    const key = newKey();
    const { text: enc, count: n } = encryptMarked('debut ((pas ferme', key);
    expect(n).toBe(0);
    expect(enc).toBe('debut ((pas ferme');
  });

  test('format « sur le fil » conforme à brocolis (nonce|ct|tag)', () => {
    const key = newKey();
    const token = encryptToken('brocolis', key);
    const inner = token.slice(
      TOKEN_PREFIX.length,
      token.length - TOKEN_SUFFIX.length,
    );
    const packed = base64.decode(inner);
    // nonce(12) + 8 octets de "brocolis" + tag(16) = 36
    expect(packed.length).toBe(12 + 8 + 16);
  });
});
