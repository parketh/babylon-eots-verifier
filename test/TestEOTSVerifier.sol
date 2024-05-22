pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/contracts/EOTSVerifier.sol";
import "../src/contracts/mocks/MockFPOracle.sol";
import "../src/libraries/Batch.sol";
import "../src/libraries/Leaf.sol";

abstract contract Helper {
  EOTSVerifier public eotsVerifier;
  MockFPOracle public fpOracle;
}

contract TestEOTSVerifier is Test, Helper {
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
    // Build batch comprising of 4 leafs, from blocks 1 to 4
    bytes32 leaf1 = Leaf(1, bytes32("1111")).hash();
    bytes32 leaf2 = Leaf(2, bytes32("2222")).hash();
    bytes32 leaf3 = Leaf(3, bytes32("3333")).hash();
    bytes32 leaf4 = Leaf(4, bytes32("4444")).hash();
    bytes32 hash12 = keccak256(abi.encodePacked(leaf1, leaf2));
    bytes32 hash34 = keccak256(abi.encodePacked(leaf3, leaf4));
    bytes32 merkleRoot = keccak256(abi.encodePacked(hash12, hash34));

    // Commit batch pub rand
    BatchKey memory batchKey = BatchKey(1, "fp1", 1, 4);
    eotsVerifier.commitPubRandBatch(batchKey, "0", merkleRoot);

    // Verify pub rand at each height
    bytes32[] memory proof = new bytes32[](2);
    proof[0] = leaf2;
    proof[1] = hash34;
    eotsVerifier.verifyPubRandAtBlock(batchKey, 1, "1111", proof);
  }

  function test_RevertIfIncorrectPubRand() public {
    // Build batch comprising of 2 leafs, from blocks 1 to 2
    bytes32 leaf1 = Leaf(1, bytes32("1111")).hash();
    bytes32 leaf2 = Leaf(2, bytes32("2222")).hash();
    bytes32 merkleRoot = keccak256(abi.encodePacked(leaf1, leaf2));

    // Commit batch pub rand
    BatchKey memory batchKey = BatchKey(1, "fp1", 1, 2);
    eotsVerifier.commitPubRandBatch(batchKey, "0", merkleRoot);

    // Verify with incorrect pub rand data should fail
    bytes32[] memory proof = new bytes32[](1);
    proof[0] = leaf2;
    vm.expectRevert(abi.encodeWithSignature("InvalidMerkleProof()"));
    eotsVerifier.verifyPubRandAtBlock(batchKey, 1, "1234", proof);
  }
}
