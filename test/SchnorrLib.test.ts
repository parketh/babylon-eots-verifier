// Source: https://github.com/noot/schnorr-verify/blob/master/test/schnorr-test.js

import { expect } from "chai";
import { ethers } from "hardhat";
import secp256k1 from "secp256k1";
import bs58check from "bs58check";
import assert from "assert";
import BigInteger from "bigi";
import { sign } from "../utils/schnorr.utils";

const arrayify = ethers.utils.arrayify;

describe("SchnorrLib", function () {
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
    const msg = arrayify(
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

    const privRand = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
    );
    var sig = sign(privKey, privRand.toBuffer(32), msg);

    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;

    expect(await schnorr.verify(parity, px, msg, e, s)).to.equal(true);
  });
});
