const { ethers } = require("hardhat");
const secp256k1 = require("secp256k1");
const arrayify = ethers.utils.arrayify;

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
  var R = secp256k1.publicKeyCreate(k);

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, m, publicKey);

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul(x, e);

  // s = k + xe
  var s = secp256k1.privateKeyTweakAdd(k, xe);
  return { R, s, e };
}

function challenge(R, m, publicKey) {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var R_uncomp = secp256k1.publicKeyConvert(R, false);
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
}

function hash(types, values) {
  return arrayify(
    ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(types, values))
  );
}

function encode(types, values) {
  return ethers.utils.defaultAbiCoder.encode(types, values);
}

module.exports = { sign, hash, encode };
