// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { IEOTSVerifier } from "./interfaces/IEOTSVerifier.sol";
import { IPubRandRegistry } from "./interfaces/IPubRandRegistry.sol";
import "./libraries/Batch.sol";

contract EOTSVerifier is IEOTSVerifier, IPubRandRegistry {
  using BatchLib for BatchKey;

  // IFPOracle public immutable fpOracle;

  error InvalidBlockRange();

  mapping(BatchId => bytes32) public merkleRoots;
  mapping(BatchId => uint64) public lastCommittedBlocks;

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
    // Verify proof of possession of fp btc key
    // Write merkle root to storage
    // Emit event
  }

  /// @notice Verify caller's proof of possession of finality provider btc key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param signedMsg Signed message
  function _verifyProofOfPossession(bytes memory proofOfPossession, BatchKey memory signedMsg)
    internal
    pure
  {
    // TODO: Implement verification logic
    // We need to agree on format of the signed message
    // For now, assume signed msg is keccak(fpBtcPublicKey, chainId, fromBlock, toBlock, merkleRoot)
  }

  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  function verifyPubRandAtBlock(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 publicNumber,
    bytes32[] calldata merkleProof
  ) external {
    // Hash calldata to get batch id
    // Retrieve merkle root from storage
    // Hash calldata to get leaf
    // Verify merkle proof
    // Return result
  }

  function verifyEots(uint32 chainId, string[] calldata fpBtcPublicKeys, bytes[] calldata sigs)
    external
  {
    // TODO
  }
}
