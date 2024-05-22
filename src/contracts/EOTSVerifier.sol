// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { IEOTSVerifier } from "../interfaces/IEOTSVerifier.sol";
import { IPubRandRegistry } from "../interfaces/IPubRandRegistry.sol";
import { IFPOracle } from "../interfaces/IFPOracle.sol";
import "../libraries/Batch.sol";
import "../libraries/Leaf.sol";

error InvalidBlockRange();
error InvalidMerkleProof();

contract EOTSVerifier is IPubRandRegistry {
  using BatchLib for BatchKey;
  using LeafLib for Leaf;

  mapping(BatchId => bytes32) public merkleRoots;
  mapping(BatchId => uint64) public lastCommittedBlocks;
  IFPOracle public immutable fpOracle;

  constructor(IFPOracle _fpOracle) {
    fpOracle = _fpOracle;
  }

  /// @notice Commit a batch of EOTS public randomness
  /// @param batchKey Batch key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param merkleRoot Merkle root of the batch
  function commitPubRandBatch(
    BatchKey calldata batchKey,
    bytes calldata proofOfPossession,
    bytes32 merkleRoot
  ) external {
    // Run validity checks
    BatchId batchId = batchKey.toId();
    uint64 lastCommittedBlock = lastCommittedBlocks[batchId];
    if (
      batchKey.fromBlock >= batchKey.toBlock || batchKey.fromBlock < block.number
        || batchKey.fromBlock <= lastCommittedBlock
    ) {
      revert InvalidBlockRange();
    }

    // Verify proof of possession of fp btc key
    _verifyProofOfPossession(proofOfPossession, batchKey);

    // Write merkle root to storage
    merkleRoots[batchId] = merkleRoot;

    // Emit event
    emit CommitPubRandBatch(
      batchKey.chainId, batchKey.fpBtcPublicKey, batchKey.fromBlock, batchKey.toBlock, merkleRoot
    );
  }

  /// @notice Verify caller's proof of possession of finality provider btc key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param signedMsg Signed message
  function _verifyProofOfPossession(bytes memory proofOfPossession, BatchKey memory signedMsg)
    internal
    pure
  {
    assert(true);
    // TODO: Implement verification logic
    // We need to agree on format of the signed message
    // For now, assume signed msg is keccak(fpBtcPublicKey, chainId, fromBlock, toBlock, merkleRoot)
  }

  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  /// @param batchKey Batch key
  /// @param atBlock Block number at which the public randomness was committed
  /// @param publicNumber Committed public number
  /// @param merkleProof Merkle proof of the public number
  function verifyPubRandAtBlock(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 publicNumber,
    bytes32[] calldata merkleProof
  ) public view {
    // Retrieve merkle root from storage
    BatchId batchId = batchKey.toId();
    bytes32 merkleRoot = merkleRoots[batchId];

    // Hash calldata to get leaf
    Leaf memory leaf = Leaf(atBlock, publicNumber);
    bytes32 hashedLeaf = leaf.hash();

    // Verify merkle proof
    if (!MerkleProof.verify(merkleProof, merkleRoot, hashedLeaf)) {
      revert InvalidMerkleProof();
    }
  }

  // function verifyEots(uint32 chainId, string[] calldata fpBtcPublicKeys, bytes[] calldata sigs)
  //   external
  // {
  //   // TODO
  // }
}
