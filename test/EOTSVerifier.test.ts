import { ethers } from "hardhat";
import secp256k1 from "secp256k1";
import assert from "assert";
import bs58check from "bs58check";
import BigInteger from "bigi";

import EOTS from "../utils/EOTS.evm.utils";
import { sign, hash, encode, orderedHash } from "../utils/schnorr.utils";

const arrayify = ethers.utils.arrayify;

describe("EOTSVerifier", function () {
  it("Should verify EOTS signature for single FP", async function () {
    // Params
    const chainId = 1;
    const fromBlock = 5;
    const toBlock = 8;
    const epochSize = toBlock - fromBlock + 1;

    // Deploy contracts
    const FPOracle = await ethers.getContractFactory("MockFPOracle");
    const fpOracle = await FPOracle.deploy();
    await fpOracle.deployed();

    const SchnorrLib = await ethers.getContractFactory("SchnorrLib");
    const schnorrLib = await SchnorrLib.deploy();
    await schnorrLib.deployed();

    const EOTSVerifier = await ethers.getContractFactory("EOTSVerifier", {
      libraries: {
        SchnorrLib: schnorrLib.address,
      },
    });
    const eotsVerifier = await EOTSVerifier.deploy(
      chainId,
      fromBlock,
      epochSize,
      fpOracle.address
    );
    await eotsVerifier.deployed();

    // Create EOTS helper
    const eots = new EOTS();

    // Hard code key pair and randomness
    const privKeyBase58 =
      "L4wJ9vYZ8NK4HsP7MgbohfBeXR2xDQvAa7jmB6h51B7ZyferqkFV";
    const privKeyUint8Array = bs58check.decode(privKeyBase58).slice(1, 33);
    assert(
      secp256k1.privateKeyVerify(privKeyUint8Array),
      "Invalid private key"
    );
    const privKey = BigInteger.fromBuffer(privKeyUint8Array);
    const pubKey = eots.getPublicKey(privKey);

    // Create public randomness
    const privRand5 = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
    );
    const pubRand5 = eots.getPublicKeyAsPoint(privRand5).affineX;
    const privRand6 = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b48"
    );
    const pubRand6 = eots.getPublicKeyAsPoint(privRand6).affineX;
    const privRand7 = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b49"
    );
    const pubRand7 = eots.getPublicKeyAsPoint(privRand7).affineX;
    const privRand8 = BigInteger.fromHex(
      "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b50"
    );
    const pubRand8 = eots.getPublicKeyAsPoint(privRand8).affineX;

    // Build batch of pub rands comprising of 4 leafs, from blocks 5 to 8
    const leaf5 = hash(
      ["uint64", "bytes32"],
      [fromBlock, pubRand5.toBuffer(32)]
    );
    const leaf6 = hash(
      ["uint64", "bytes32"],
      [fromBlock + 1, pubRand6.toBuffer(32)]
    );
    const leaf7 = hash(
      ["uint64", "bytes32"],
      [fromBlock + 2, pubRand7.toBuffer(32)]
    );
    const leaf8 = hash(
      ["uint64", "bytes32"],
      [fromBlock + 3, pubRand8.toBuffer(32)]
    );
    const hash56 = orderedHash(leaf5, leaf6);
    const hash78 = orderedHash(leaf7, leaf8);
    const merkleRoot = orderedHash(hash56, hash78);

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
    const pubKeyAsPoint = eots.getPublicKeyAsPoint(privKey);
    const privRand = Buffer.from("random byte array with length 32"); // String has length 32 - do not change
    const sig = sign(privKeyUint8Array, privRand, msg);
    const parity = eots.getParity(pubKeyAsPoint);
    const px = pubKeyAsPoint.affineX;
    const proofOfPossession = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [parity, px.toBuffer(32), msg, sig.e, sig.s]
    );

    // Commit pub rand batch
    await eotsVerifier.commitPubRandBatch(
      1,
      pubKey,
      proofOfPossession,
      merkleRoot
    );

    // Set voting power for single FP.
    await fpOracle.setL2BlockNumber(4);
    await fpOracle.setVotingPower(1, 5, 100);
    await fpOracle.setVotingPowerFor(1, 5, pubKey, 100);

    // Sign block.
    const outputRoot = Buffer.from("random byte array output root 32");
    const { e: e5, s: sig5 } = eots.sign(privKey, privRand5, outputRoot);
    const signature5 = encode(
      ["uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        parity,
        arrayify(px.toBuffer(32)),
        outputRoot,
        arrayify(e5.toBuffer(32)),
        arrayify(sig5.toBuffer(32)),
      ]
    );

    // Verify EOTS signature.
    const eotsData = {
      fpBtcPublicKey: arrayify(pubKey),
      pubRand: arrayify(pubRand5.toBuffer(32)),
      merkleProof: [leaf6, hash78],
      signature: signature5,
      parity,
      px: arrayify(px.toBuffer(32)),
      e: arrayify(e5.toBuffer(32)),
      sig: arrayify(sig5.toBuffer(32)),
    };
    await eotsVerifier.verifyEots(epoch, 5, outputRoot, [eotsData]);
  });
});
