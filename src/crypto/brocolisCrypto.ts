//
//  brocolisCrypto.ts
//  Messagerie 🥦
//
//  Chiffrement sélectif AES-256-GCM, compatible « au format de jeton » près
//  avec le proxy Rust brocolis (https://github.com/maxlestage/brocolis).
//
//  Schéma sélectif : seul le contenu explicitement marqué est chiffré.
//   - À l'envoi, tout segment `((texte secret))` est chiffré et remplacé par un
//     jeton `[[BROCOLIS:v1:<base64>]]`.
//   - À l'affichage, tout jeton `[[BROCOLIS:v1:<base64>]]` est déchiffré et
//     remplacé par son texte clair.
//
//  Le jeton encode `nonce (12 octets) || ciphertext || tag (16 octets)`, ce qui
//  correspond exactement à l'empaquetage de la crate Rust `aes-gcm` (qui appose
//  le tag à la fin du ciphertext). Deux appareils partageant la même clé voient
//  donc le clair, alors qu'un transport intermédiaire ne voit que le jeton.
//

import { gcm } from '@noble/ciphers/aes';
import { utf8ToBytes, bytesToUtf8 } from '@noble/ciphers/utils';
import { base64 } from '@scure/base';
import * as Crypto from 'expo-crypto';

export const TOKEN_PREFIX = '[[BROCOLIS:v1:';
export const TOKEN_SUFFIX = ']]';
export const PLAIN_OPEN = '((';
export const PLAIN_CLOSE = '))';

export const KEY_LENGTH = 32; // AES-256
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

// MARK: Gestion de la clé

/** Génère une clé AES-256 aléatoire (CSPRNG) et la renvoie en base64. */
export function generateKeyBase64(): string {
  return base64.encode(Crypto.getRandomBytes(KEY_LENGTH));
}

/** Décode et valide une clé base64 (32 octets). Lève en cas d'erreur. */
export function keyBytesFromBase64(b64: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = base64.decode(b64.trim());
  } catch {
    throw new Error('Clé base64 invalide.');
  }
  if (raw.length !== KEY_LENGTH) {
    throw new Error(`La clé doit faire ${KEY_LENGTH} octets, reçu ${raw.length}.`);
  }
  return raw;
}

// MARK: Jeton unitaire

/** Chiffre `plaintext` et renvoie un jeton `[[BROCOLIS:v1:<base64>]]`. */
export function encryptToken(plaintext: string, keyBytes: Uint8Array): string {
  const nonce = Crypto.getRandomBytes(NONCE_LENGTH);
  const sealed = gcm(keyBytes, nonce).encrypt(utf8ToBytes(plaintext)); // ciphertext||tag
  const packed = new Uint8Array(nonce.length + sealed.length);
  packed.set(nonce, 0);
  packed.set(sealed, nonce.length);
  return TOKEN_PREFIX + base64.encode(packed) + TOKEN_SUFFIX;
}

/** Déchiffre la partie base64 d'un jeton (sans préfixe/suffixe). Lève si KO. */
export function decryptTokenBase64(b64: string, keyBytes: Uint8Array): string {
  let packed: Uint8Array;
  try {
    packed = base64.decode(b64);
  } catch {
    throw new Error('Jeton chiffré corrompu.');
  }
  if (packed.length < NONCE_LENGTH + TAG_LENGTH) {
    throw new Error('Jeton chiffré corrompu.');
  }
  const nonce = packed.slice(0, NONCE_LENGTH);
  const ciphertextAndTag = packed.slice(NONCE_LENGTH);
  const plain = gcm(keyBytes, nonce).decrypt(ciphertextAndTag);
  return bytesToUtf8(plain);
}

// MARK: Chiffrement / déchiffrement sélectif (best effort)

export interface SelectiveResult {
  text: string;
  count: number;
}

/**
 * Remplace chaque `((secret))` par un jeton chiffré.
 * Un segment dont le chiffrement échoue est laissé tel quel.
 */
export function encryptMarked(input: string, keyBytes: Uint8Array): SelectiveResult {
  let out = '';
  let count = 0;
  let rest = input;

  while (true) {
    const open = rest.indexOf(PLAIN_OPEN);
    if (open === -1) break;
    const afterOpen = rest.slice(open + PLAIN_OPEN.length);
    const close = afterOpen.indexOf(PLAIN_CLOSE);
    if (close === -1) break; // marqueur non fermé : on laisse intact

    const secret = afterOpen.slice(0, close);
    out += rest.slice(0, open);
    try {
      out += encryptToken(secret, keyBytes);
      count += 1;
    } catch {
      out += PLAIN_OPEN + secret + PLAIN_CLOSE;
    }
    rest = afterOpen.slice(close + PLAIN_CLOSE.length);
  }
  out += rest;
  return { text: out, count };
}

/**
 * Remplace chaque jeton `[[BROCOLIS:v1:...]]` par son texte clair.
 * Un jeton illisible (mauvaise clé, corruption) est laissé tel quel.
 */
export function decryptTokens(input: string, keyBytes: Uint8Array): SelectiveResult {
  let out = '';
  let count = 0;
  let rest = input;

  while (true) {
    const start = rest.indexOf(TOKEN_PREFIX);
    if (start === -1) break;
    const afterPrefix = rest.slice(start + TOKEN_PREFIX.length);
    const end = afterPrefix.indexOf(TOKEN_SUFFIX);
    if (end === -1) break;

    const b64 = afterPrefix.slice(0, end);
    out += rest.slice(0, start);
    try {
      out += decryptTokenBase64(b64, keyBytes);
      count += 1;
    } catch {
      out += TOKEN_PREFIX + b64 + TOKEN_SUFFIX;
    }
    rest = afterPrefix.slice(end + TOKEN_SUFFIX.length);
  }
  out += rest;
  return { text: out, count };
}

/** Indique si un texte contient au moins un jeton chiffré. */
export function containsToken(text: string): boolean {
  return text.includes(TOKEN_PREFIX);
}
