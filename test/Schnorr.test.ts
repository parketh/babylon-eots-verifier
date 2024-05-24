// Source: https://github.com/noot/schnorr-verify/blob/master/test/schnorr-test.js

import { expect } from "chai";
import { ethers } from "hardhat";
import secp256k1 from "secp256k1";
import bs58check from "bs58check";
import assert from "assert";
import { sign } from "./utils/crypto";

const arrayify = ethers.utils.arrayify;

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

    // Hard code test Bitcoin private key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    const pubKey = secp256k1.publicKeyCreate(privKey);

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

    // console.log({
    //   parity,
    //   px: Buffer.from(px).toString("hex"),
    //   msg: Buffer.from(msg).toString("hex"),
    //   e: Buffer.from(e).toString("hex"),
    //   s: s.toString("hex"),
    // });

    expect(await schnorr.verify(parity, px, msg, e, s)).to.equal(true);
  });
});
