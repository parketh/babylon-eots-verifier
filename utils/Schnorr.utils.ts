// Source: https://github.com/noot/schnorr-verify

import { ethers } from "ethers";
import {
  publicKeyCreate,
  privateKeyTweakMul,
  privateKeyTweakAdd,
  publicKeyConvert,
} from "secp256k1";
import BigInteger from "bigi";
import ecurve from "ecurve";
import {
  bytesToBigInt64,
  bytesToHex,
  ecrecover,
  hexToBytes,
} from "@ethereumjs/util";

const arrayify = ethers.utils.arrayify;
const curve = ecurve.getCurveByName("secp256k1");

const Q = BigInteger.fromHex(
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
const HALF_Q = BigInteger.fromHex(
  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
);

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

const hash = (types: string[], values: any[]): Uint8Array => {
  return arrayify(
    ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(types, values))
  );
};

const encode = (types: string[], values: any[]) => {
  return ethers.utils.defaultAbiCoder.encode(types, values);
};

export { sign, verify, hash, encode };
