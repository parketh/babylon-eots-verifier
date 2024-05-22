// Source: https://github.com/noot/schnorr-verify/blob/master/test/schnorr-test.js

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { randomBytes } = require("crypto");
const secp256k1 = require("secp256k1");
const arrayify = ethers.utils.arrayify;

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = randomBytes(32);
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

describe("Schnorr", function () {
  it("Should verify a signature", async function () {
    const SchnorrLib = await ethers.getContractFactory("SchnorrLib");
    const schnorrLib = await SchnorrLib.deploy();
    await schnorrLib.deployed();

    const Schnorr = await ethers.getContractFactory("MockSchnorr", {
      libraries: {
        SchnorrLib: schnorrLib.address,
      },
    });
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // generate privKey
    let privKey;
    do {
      privKey = randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privKey));

    var publicKey = secp256k1.publicKeyCreate(privKey);

    // message
    // TODO: use a real message
    var m = ethers.utils.solidityKeccak256(
      ["uint32", "string", "uint32", "uint32", "bytes32"],
      [1, "hello", 2, 3, "0x12345678"]
    );

    var sig = sign(m, privKey);

    expect(
      await schnorr.verify(
        publicKey[0] - 2 + 27,
        publicKey.slice(1, 33),
        arrayify(m),
        sig.e,
        sig.s
      )
    ).to.equal(true);
  });
});
