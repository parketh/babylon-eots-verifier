pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "src/contracts/EOTSVerifier.sol";
import "src/contracts/mocks/MockFPOracle.sol";
import "src/libraries/Batch.sol";
import "src/libraries/Leaf.sol";
import "src/libraries/Schnorr.sol";

abstract contract Helper {
  EOTSVerifier public eotsVerifier;
  MockFPOracle public fpOracle;
}

contract TestPubRandRegistry is Test, Helper {
  using LeafLib for Leaf;

  function setUp() public {
    // Deploy contracts
    fpOracle = new MockFPOracle();
    eotsVerifier = new EOTSVerifier(fpOracle);

    // Register single FP in mock oracle
    fpOracle.setVotingPower(1, 1);
    fpOracle.setVotingPower(1, "fp1", 1);
  }

  function test_CommitAndVerifyPubRandBatch() public {
    // Setup
    uint32 chainId = 1;
    string memory fpBtcPublicKey = "fp1";
    uint64 fromBlock = 1;
    uint64 toBlock = 4;

    // Build batch comprising of 4 leafs, from blocks 1 to 4
    bytes32 leaf1 = Leaf(1, bytes32("1111")).hash();
    bytes32 leaf2 = Leaf(2, bytes32("2222")).hash();
    bytes32 leaf3 = Leaf(3, bytes32("3333")).hash();
    bytes32 leaf4 = Leaf(4, bytes32("4444")).hash();
    bytes32 hash12 = keccak256(abi.encodePacked(leaf1, leaf2));
    bytes32 hash34 = keccak256(abi.encodePacked(leaf3, leaf4));
    bytes32 merkleRoot = keccak256(abi.encodePacked(hash12, hash34));

    // Commit batch pub rand
    BatchKey memory batchKey = BatchKey(chainId, fpBtcPublicKey, fromBlock, toBlock);
    bytes32 hashedMsg =
      keccak256(abi.encodePacked(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot));

    // Generated in `TestSchnorr.js` and hardcoded here
    uint8 parity = 28;
    bytes32 px = 0x674c62bf12e0a822405347f5731cb2a5bde98dd9161b37c2a3745cfe8af37da0;
    bytes32 e = 0xc594792d34a81511d19db615bc4c954e0b4d8a1cddff06e93772bb3322937f05;
    bytes32 sig = 0xd823c622af78d2e40a513bcf2076b66137582c0a8afb47911709df4848162680;
    bytes memory proofOfPossession = SchnorrLib.pack(parity, px, hashedMsg, e, sig);
    eotsVerifier.commitPubRandBatch(batchKey, proofOfPossession, merkleRoot);

    // Verify pub rand at each height
    bytes32[] memory proof = new bytes32[](2);
    proof[0] = leaf2;
    proof[1] = hash34;
    require(eotsVerifier.verifyPubRandAtBlock(batchKey, 1, "1111", proof), "Invalid merkle proof");
  }

  function test_RevertIfIncorrectProofOfPossession() public {
    // Build batch comprising of 2 leafs, from blocks 1 to 2
    bytes32 leaf1 = Leaf(1, bytes32("1111")).hash();
    bytes32 leaf2 = Leaf(2, bytes32("2222")).hash();
    bytes32 merkleRoot = keccak256(abi.encodePacked(leaf1, leaf2));

    // Pass in random proof of possession
    BatchKey memory batchKey = BatchKey(1, "fp1", 1, 2);
    bytes memory wrongProofOfPossession =
      hex"000000000000000000000000000000000000000000000000000000000000001c674c62bf12e0a822406347f5731cb2a5bde98dd9161b37c2a3745cfe8af37da0f61df6719895921b59bda45d7b16511ad2641ed6bbffd224feba9dd4af291e2a23f4fc75f258ad93758e900dc0632a071baec011ac309d2f6cd8b210a7d7c25e1f6dbf3979edf4418d5c9220737cea69e1f7947bc68a660be283e1d5f07c1812";
    vm.expectRevert(abi.encodeWithSignature("InvalidProofOfPossession()"));
    eotsVerifier.commitPubRandBatch(batchKey, wrongProofOfPossession, merkleRoot);
  }

  function test_IncorrectPubRand() public {
    // Setup
    uint32 chainId = 1;
    string memory fpBtcPublicKey = "fp1";
    uint64 fromBlock = 1;
    uint64 toBlock = 2;

    // Build batch comprising of 2 leafs, from blocks 1 to 2
    bytes32 leaf1 = Leaf(1, bytes32("1111")).hash();
    bytes32 leaf2 = Leaf(2, bytes32("2222")).hash();
    bytes32 merkleRoot = keccak256(abi.encodePacked(leaf1, leaf2));

    // Commit batch pub rand
    BatchKey memory batchKey = BatchKey(1, "fp1", 1, 2);
    bytes32 hashedMsg =
      keccak256(abi.encodePacked(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot));

    // Generated in `TestSchnorr.js` and hardcoded here
    uint8 parity = 28;
    bytes32 px = 0x674c62bf12e0a822405347f5731cb2a5bde98dd9161b37c2a3745cfe8af37da0;
    bytes32 e = 0x23f4fc75f258ad93758e900dc0632a071baec011ac309d2f6cd8b210a7d7c25e;
    bytes32 sig = 0x1f6dbf3979edf4418d5c9220737cea69e1f7947bc68a660be283e1d5f07c1812;
    bytes memory proofOfPossession = SchnorrLib.pack(parity, px, hashedMsg, e, sig);
    eotsVerifier.commitPubRandBatch(batchKey, proofOfPossession, merkleRoot);

    // Verify with incorrect pub rand data should fail
    bytes32[] memory proof = new bytes32[](1);
    proof[0] = leaf2;
    require(
      !eotsVerifier.verifyPubRandAtBlock(batchKey, 1, "1234", proof), "Merkle proof should fail"
    );
  }
}
