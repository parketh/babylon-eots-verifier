// Source: https://github.com/noot/schnorr-verify/blob/master/test/schnorr-test.js

import { Contract } from "ethers";

import { expect } from "chai";
import { ethers, network } from "hardhat";
import secp256k1 from "secp256k1";
import bs58check from "bs58check";
import assert from "assert";
import { sign, hash, encode } from "./utils/crypto";

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

  // Public randomness by block
  const pubRand5 = ethers.utils.formatBytes32String(
    "random byte array with num 0005"
  );
  const pubRand6 = ethers.utils.formatBytes32String(
    "random byte array with num 0006"
  );
  const pubRand7 = ethers.utils.formatBytes32String(
    "random byte array with num 0007"
  );
  const pubRand8 = ethers.utils.formatBytes32String(
    "random byte array with num 0008"
  );

  // Build batch comprising of 4 leafs, from blocks 5 to 8
  const leaf5 = hash(["uint64", "bytes32"], [fromBlock, pubRand5]);
  const leaf6 = hash(["uint64", "bytes32"], [fromBlock + 1, pubRand6]);
  const leaf7 = hash(["uint64", "bytes32"], [fromBlock + 2, pubRand7]);
  const leaf8 = hash(["uint64", "bytes32"], [fromBlock + 3, pubRand8]);
  const hash56 = hash(["bytes32", "bytes32"], [leaf5, leaf6]);
  const hash78 = hash(["bytes32", "bytes32"], [leaf7, leaf8]);
  const merkleRoot = hash(["bytes32", "bytes32"], [hash56, hash78]);

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
    eotsVerifier = await EOTSVerifier.deploy(fpOracle.address);
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
    // keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint32", "bytes", "uint64", "uint64", "bytes32"],
        [chainId, pubKey, fromBlock, toBlock, Buffer.from(merkleRoot)]
      )
    );

    // Sign message
    const sig = sign(msg, privKey);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const proofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch
    const batchKey = {
      chainId,
      fromBlock,
      toBlock,
    };
    await eotsVerifier.commitPubRandBatch(
      batchKey,
      pubKey,
      proofOfPossession,
      merkleRoot
    );

    // Verify pub rand batch
    const proof = [Buffer.from(leaf6), Buffer.from(hash78)];
    const isValid = await eotsVerifier.verifyPubRandAtBlock(
      batchKey,
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
    // keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint32", "bytes", "uint64", "uint64", "bytes32"],
        [chainId, pubKey, fromBlock, toBlock, Buffer.from(merkleRoot)]
      )
    );

    // Sign message
    // Build wrong proof of possession
    const sig = sign(msg, privKey);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(0, 32); // deliberately use the wrong pubkey
    const e = sig.e;
    const s = sig.s;
    const wrongProofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Try to commit pub rand batch
    const batchKey = {
      chainId,
      fromBlock,
      toBlock,
    };
    expect(async () => {
      await eotsVerifier.commitPubRandBatch(
        batchKey,
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
    // keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint32", "bytes", "uint64", "uint64", "bytes32"],
        [chainId, pubKey, fromBlock, toBlock, Buffer.from(merkleRoot)]
      )
    );

    // Sign message and build proof of possession
    const sig = sign(msg, privKey);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const wrongProofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch twice
    const batchKey = {
      chainId,
      fromBlock,
      toBlock,
    };
    await eotsVerifier.commitPubRandBatch(
      batchKey,
      pubKey,
      wrongProofOfPossession,
      merkleRoot
    );
    expect(async () => {
      await eotsVerifier.commitPubRandBatch(
        batchKey,
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
    // keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    const msg = arrayify(
      ethers.utils.solidityKeccak256(
        ["uint32", "bytes", "uint64", "uint64", "bytes32"],
        [chainId, pubKey, fromBlock, toBlock, Buffer.from(merkleRoot)]
      )
    );

    /// Sign message
    const sig = sign(msg, privKey);
    const parity = pubKey[0] - 2 + 27;
    const px = pubKey.slice(1, 33);
    const e = sig.e;
    const s = sig.s;
    const proofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px, msg, e, s]
    );

    // Commit pub rand batch
    const batchKey = {
      chainId,
      fromBlock,
      toBlock,
    };
    await eotsVerifier.commitPubRandBatch(
      batchKey,
      pubKey,
      proofOfPossession,
      merkleRoot
    );

    // Verify pub rand batch
    const proof = [Buffer.from(leaf6), Buffer.from(hash78)];
    const isValid = await eotsVerifier.verifyPubRandAtBlock(
      batchKey,
      pubKey,
      fromBlock,
      pubRand6, // wrong pub rand
      proof
    );
    expect(isValid).to.be.false;
  });
});
