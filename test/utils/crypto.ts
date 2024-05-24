import { ethers } from "hardhat";
import {
  publicKeyCreate,
  privateKeyTweakMul,
  privateKeyTweakAdd,
  publicKeyConvert,
} from "secp256k1";

const arrayify = ethers.utils.arrayify;

const sign = (
  m: Uint8Array,
  x: Uint8Array
): { R: Uint8Array; s: Uint8Array; e: Uint8Array } => {
  var publicKey = publicKeyCreate(x);

  // R = G * k
  var k = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
  var R = publicKeyCreate(k);

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, m, publicKey);

  // xe = x * e
  var xe = privateKeyTweakMul(x, e);

  // s = k + xe
  var s = privateKeyTweakAdd(k, xe);
  return { R, s, e };
};

const challenge = (
  R: Uint8Array,
  m: Uint8Array,
  publicKey: Uint8Array
): Uint8Array => {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var R_uncomp = publicKeyConvert(R, false);
  var R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(
    12,
    32
  );

  // e = keccak256(address(R) || compressed publicKey || m)
  var e = arrayify(
    ethers.utils.solidityKeccak256(
      ["address", "uint8", "bytes32", "bytes32"],
      [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), m]
    )
  );

  return e;
};

const hash = (types: string[], values: any[]): Uint8Array => {
  return arrayify(
    ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(types, values))
  );
};

const encode = (types: string[], values: any[]) => {
  return ethers.utils.defaultAbiCoder.encode(types, values);
};

export { sign, hash, encode };
