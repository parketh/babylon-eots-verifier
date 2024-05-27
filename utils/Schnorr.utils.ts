// Source: https://github.com/noot/schnorr-verify

import { ethers } from "ethers";
import {
  publicKeyCreate,
  privateKeyTweakMul,
  privateKeyTweakAdd,
  publicKeyConvert,
} from "secp256k1";
import BigInteger from "bigi";
import { bytesToHex, ecrecover, hexToBytes } from "@ethereumjs/util";

const arrayify = ethers.utils.arrayify;

const Q = BigInteger.fromHex(
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
const HALF_Q = BigInteger.fromHex(
  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
);

/**
 * Sign a message using the Schnorr signature scheme.
 * @param {Uint8Array} privKey - Private key
 * @param {Uint8Array} privRand - Private randomness
 * @param {Uint8Array} msg - Message to sign
 * @returns {{ R: Uint8Array, s: Uint8Array, e: Uint8Array }} - Public randomness, commitment and signature
 */
const sign = (
  privKey: Uint8Array,
  privRand: Uint8Array,
  msg: Uint8Array
): { R: Uint8Array; s: Uint8Array; e: Uint8Array } => {
  var publicKey = publicKeyCreate(privKey);

  // R = G * k
  var R = publicKeyCreate(privRand);

  // Compute commitment
  var e = commitment(R, msg, publicKey);

  // de = d * e
  var de = privateKeyTweakMul(privKey, e);

  // s = k + de
  var s = privateKeyTweakAdd(privRand, de);
  return { R, s, e };
};

/**
 * Verify a message signed using the Schnorr signature scheme.
 * @param {number} parity - Parity of the public key
 * @param {Uint8Array} pubKeyX - X-coordinate of the public key
 * @param {Uint8Array} msg - Message
 * @param {Uint8Array} R - Public randomness
 * @param {Uint8Array} s - Signature
 * @param {Uint8Array} e - Commitment
 * @returns {boolean} - If the signature is valid
 */
const verify = (
  parity: number,
  pubKeyX: Uint8Array,
  msg: Uint8Array,
  R: Uint8Array,
  s: Uint8Array,
  e: Uint8Array
): boolean => {
  if (BigInteger.fromBuffer(pubKeyX).compareTo(HALF_Q) >= 0) {
    throw new Error("Invalid public key");
  }
  if (BigInteger.fromBuffer(s).compareTo(Q) >= 0) {
    throw new Error("Signature overflow");
  }

  // Compure sp and ep
  console.log({
    msg: Buffer.from(msg).toString("hex"),
    s: BigInteger.fromBuffer(s).toString(16),
    pubKeyX: BigInteger.fromBuffer(pubKeyX).toString(16),
    e: BigInteger.fromBuffer(e).toString(16),
  });
  const sp = Q.subtract(
    BigInteger.fromBuffer(s).multiply(BigInteger.fromBuffer(pubKeyX)).mod(Q)
  ).mod(Q);
  const ep = Q.subtract(
    BigInteger.fromBuffer(e).multiply(BigInteger.fromBuffer(pubKeyX)).mod(Q)
  ).mod(Q);
  if (sp.equals(BigInteger.ZERO)) {
    throw new Error("sp is zero");
  }

  const recoveredPublicKey = ecrecover(
    sp.toBuffer(32),
    BigInt(parity),
    Buffer.from(pubKeyX),
    ep.toBuffer(32)
  );
  const recoveredAddress = bytesToHex(
    hexToBytes(ethers.utils.keccak256(recoveredPublicKey)).slice(12, 32)
  );

  return (
    enforcePrefix(Buffer.from(e).toString("hex")) ===
    enforcePrefix(
      ethers.utils.solidityKeccak256(
        ["address", "uint8", "bytes32", "bytes32"],
        [recoveredAddress, parity, Buffer.from(pubKeyX), msg]
      )
    )
  );
};

/**
 * Compute the commitment for a message.
 * @param {Uint8Array} pubRand - Public randomness
 * @param {Uint8Array} msg - Message
 * @param {Uint8Array} pubKey - Public key
 * @returns {Uint8Array} - Commitment
 */
const commitment = (
  pubRand: Uint8Array,
  msg: Uint8Array,
  pubKey: Uint8Array
): Uint8Array => {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var pubRandUncompressed = publicKeyConvert(pubRand, false);
  var addressR = arrayify(
    ethers.utils.keccak256(pubRandUncompressed.slice(1, 65))
  ).slice(12, 32);

  // e = keccak256(address(R) || compressed publicKey || m)
  var e = arrayify(
    ethers.utils.solidityKeccak256(
      ["address", "uint8", "bytes32", "bytes32"],
      [addressR, pubKey[0] + 27 - 2, pubKey.slice(1, 33), msg]
    )
  );

  return e;
};

/**
 * Add the 0x prefix to an address if it is missing.
 * @param {string} addr - Address
 * @returns {string} - Address with enforced prefix
 */
const enforcePrefix = (addr: string): string => {
  let address = addr.toLowerCase();
  if (addr.startsWith("0x")) {
    address = addr.slice(2);
  }
  // Pad to 64 characters
  if (address.length < 64) {
    address = "0".repeat(64 - address.length) + address;
  }
  return "0x" + address;
};

/**
 * Keccak256 hash a list of values.
 * @param {string[]} types - Types of values
 * @param {any[]} values - Values to hash
 * @returns {Uint8Array} - Hash
 */
const hash = (types: string[], values: any[]): Uint8Array => {
  return arrayify(
    ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(types, values))
  );
};

/** Keccak256 hash two values, first ordering them.
 * @param {Buffer | Uint8Array} valueA - First value
 * @param {Buffer | Uint8Array} valueB - Second value
 * @returns {Uint8Array} - Hash
 */
const orderedHash = (
  valueA: Buffer | Uint8Array,
  valueB: Buffer | Uint8Array
): Uint8Array => {
  return Buffer.from(valueA).compare(valueB) < 0
    ? hash(["bytes32", "bytes32"], [valueA, valueB])
    : hash(["bytes32", "bytes32"], [valueB, valueA]);
};

/**
 * ABI encodes a list of values.
 * @param {string[]} types - Types of values
 * @param {any[]} values - Values to encode
 * @returns {string} - Encoded values
 */
const encode = (types: string[], values: any[]): string => {
  return ethers.utils.defaultAbiCoder.encode(types, values);
};

export { sign, verify, hash, orderedHash, encode, enforcePrefix };
