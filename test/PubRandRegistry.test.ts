import { Contract } from "ethers";

import { expect } from "chai";
import { ethers, network } from "hardhat";
import secp256k1 from "secp256k1";
import bs58check from "bs58check";
import assert from "assert";
import BigInteger from "bigi";
import {
  sign,
  hash,
  encode,
  enforcePrefix,
  orderedHash,
} from "../utils/schnorr.utils";

const arrayify = ethers.utils.arrayify;

describe("PubRandRegistry", function () {
  // Contracts
  let fpOracle: Contract;
  let schnorrLib: Contract;
  let eotsVerifier: Contract;

  // Params
  const chainId = 1;
  const fromBlock = 5;
  const toBlock = 8;
  const epochSize = toBlock - fromBlock + 1;

  // Public randomness by block
  const pubRand5 = BigInteger.fromHex(
    "08181dd42658f82d31b6cff6466740a64deb11fddff3a90ff06b9c34395ca5a2"
  ).toBuffer(32);
  const pubRand6 = BigInteger.fromHex(
    "a5edbfddefefe11a477ee02aca6f53eb1da567f72ca40777738174273a38140a"
  ).toBuffer(32);
  const pubRand7 = BigInteger.fromHex(
    "4f232a010ff07ac9820273ed532b7681369c81561cb4f1e6a74fc4913966facd"
  ).toBuffer(32);
  const pubRand8 = BigInteger.fromHex(
    "e6ac97b2639c3706e64594d7b724b1d99c8a326460d0bb0b92a67d4310581c1a"
  ).toBuffer(32);

  // Build batch comprising of 4 leafs, from blocks 5 to 8
  const leaf5 = hash(["uint64", "bytes32"], [fromBlock, pubRand5]);
  const leaf6 = hash(["uint64", "bytes32"], [fromBlock + 1, pubRand6]);
  const leaf7 = hash(["uint64", "bytes32"], [fromBlock + 2, pubRand7]);
  const leaf8 = hash(["uint64", "bytes32"], [fromBlock + 3, pubRand8]);
  const hash56 = orderedHash(leaf5, leaf6);
  const hash78 = orderedHash(leaf7, leaf8);
  const merkleRoot = orderedHash(hash56, hash78);

  beforeEach(async function () {
    // Reset VM
    await network.provider.send("hardhat_reset");

    // Deploy contracts
    const FPOracle = await ethers.getContractFactory("MockFPOracle");
    fpOracle = await FPOracle.deploy();
    await fpOracle.deployed();

    const SchnorrLib = await ethers.getContractFactory("SchnorrLib");
    schnorrLib = await SchnorrLib.deploy();
    await schnorrLib.deployed();

    const EOTSVerifier = await ethers.getContractFactory("EOTSVerifier", {
      libraries: {
        SchnorrLib: schnorrLib.address,
      },
    });
    eotsVerifier = await EOTSVerifier.deploy(
      chainId,
      fromBlock,
      epochSize,
      fpOracle.address
    );
    await eotsVerifier.deployed();
  });

  it("Should commit and verify a pub rand batch", async function () {
    // Hard code test Bitcoin key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    const pubKey = secp256k1.publicKeyCreate(privKey);

    // Define message
    // keccak(epoch, fpBtcPublicKey, merkleRoot)
    const epoch = 1;
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint64", "bytes", "bytes32"],
        [epoch, pubKey, Buffer.from(merkleRoot)]
      )
    );

    // Sign message
    const privRand = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
    ).toBuffer(32);
    const sig = sign(privKey, privRand, msg);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const proofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch
    await eotsVerifier.commitPubRandBatch(
      epoch,
      pubKey,
      proofOfPossession,
      merkleRoot
    );

    // Verify pub rand batch
    const proof = [Buffer.from(leaf6), Buffer.from(hash78)];
    const isValid = await eotsVerifier.verifyPubRandAtBlock(
      epoch,
      pubKey,
      fromBlock,
      pubRand5,
      proof
    );
    expect(isValid).to.be.true;
  });

  it("Should revert for incorrect proof of possession", async function () {
    // Hard code test Bitcoin key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    const pubKey = secp256k1.publicKeyCreate(privKey);

    // Define message
    // keccak(epoch, fpBtcPublicKey, merkleRoot)
    const epoch = 1;
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint64", "bytes", "bytes32"],
        [epoch, pubKey, Buffer.from(merkleRoot)]
      )
    );

    // Sign message
    // Build wrong proof of possession
    const privRand = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
    const sig = sign(privKey, privRand, msg);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(0, 32); // deliberately use the wrong pubkey
    const e = sig.e;
    const s = sig.s;
    const wrongProofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Try to commit pub rand batch
    expect(async () => {
      const epoch = 1;
      await eotsVerifier.commitPubRandBatch(
        epoch,
        pubKey,
        wrongProofOfPossession,
        merkleRoot
      );
    }).to.be.revertedWith("InvalidProofOfPossession()");
  });

  it("Should revert for duplicate pub rand commitment", async function () {
    // Hard code test Bitcoin key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    const pubKey = secp256k1.publicKeyCreate(privKey);

    // Define message
    // keccak(epoch, fpBtcPublicKey, merkleRoot)
    const epoch = 1;
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint64", "bytes", "bytes32"],
        [epoch, pubKey, Buffer.from(merkleRoot)]
      )
    );

    // Sign message and build proof of possession
    const privRand = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
    const sig = sign(privKey, privRand, msg);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const wrongProofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch twice
    await eotsVerifier.commitPubRandBatch(
      epoch,
      pubKey,
      wrongProofOfPossession,
      merkleRoot
    );
    expect(async () => {
      await eotsVerifier.commitPubRandBatch(
        epoch,
        pubKey,
        wrongProofOfPossession,
        merkleRoot
      );
    }).to.be.revertedWith("DuplicateBatch()");
  });

  it("Should detect incorrect pub rand", async function () {
    // Hard code test Bitcoin key
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKey = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(secp256k1.privateKeyVerify(privKey), "Invalid private key");
    const pubKey = secp256k1.publicKeyCreate(privKey);

    // Define message
    // keccak(epoch, fpBtcPublicKey, merkleRoot)
    const epoch = 1;
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint64", "bytes", "bytes32"],
        [epoch, pubKey, Buffer.from(merkleRoot)]
      )
    );

    /// Sign message
    const privRand = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
    const sig = sign(privKey, privRand, msg);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const proofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch
    await eotsVerifier.commitPubRandBatch(
      epoch,
      pubKey,
      proofOfPossession,
      merkleRoot
    );

    // Verify pub rand batch
    const proof = [Buffer.from(leaf6), Buffer.from(hash78)];
    const isValid = await eotsVerifier.verifyPubRandAtBlock(
      epoch,
      pubKey,
      fromBlock,
      pubRand6, // wrong pub rand
      proof
    );
    expect(isValid).to.be.false;
  });
});
