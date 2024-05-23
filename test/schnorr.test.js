// Source: https://github.com/noot/schnorr-verify/blob/master/test/schnorr-test.js

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { randomBytes } = require("crypto");
const secp256k1 = require("secp256k1");
const bs58check = require("bs58check");
const assert = require("assert");
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

    // Hard code private key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    var pubKey = secp256k1.publicKeyCreate(privKey);

    // Define message
    // keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    var msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint32", "string", "uint64", "uint64", "bytes"],
        [
          1,
          "fp1",
          1,
          4,
          Buffer.from(
            "ba02a7da2f60d0c30b1c2ee6158f779b488276630391f346ca734f4f249eede3",
            "hex"
          ),
        ]
      )
    );

    var sig = sign(msg, privKey);

    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;

    console.log({
      parity,
      px: Buffer.from(px).toString("hex"),
      msg: Buffer.from(msg).toString("hex"),
      e: Buffer.from(e).toString("hex"),
      s: s.toString("hex"),
    });

    expect(await schnorr.verify(parity, px, msg, e, s)).to.equal(true);
  });
});
