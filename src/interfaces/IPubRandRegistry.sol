// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { BatchId, BatchKey } from "../libraries/Batch.sol";

interface IPubRandRegistry {
  /// @notice Commit a batch of EOTS public randomness
  /// @param batchKey Batch key
  /// @param fpBtcPublicKey Finality provider btc public key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param merkleRoot Merkle root of the batch
  function commitPubRandBatch(
    BatchKey calldata batchKey,
    bytes calldata fpBtcPublicKey,
    bytes calldata proofOfPossession,
    bytes32 merkleRoot
  ) external;

  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  /// @param batchKey Batch key
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @param atBlock Block number at which the public randomness was committed
  /// @param pubRand Committed public number
  /// @param merkleProof Merkle proof of the public number
  /// @return isValid Whether the public number is valid
  function verifyPubRandAtBlock(
    BatchKey calldata batchKey,
    bytes calldata fpBtcPublicKey,
    uint64 atBlock,
    bytes32 pubRand,
    bytes32[] calldata merkleProof
  ) external view returns (bool);

  /// @notice Event emitted when a new batch of EOTS public randomness is committed
  /// @param chainId Chain ID
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @param fromBlock Block number at which batch starts
  /// @param toBlock Block number at which batch ends
  /// @param merkleRoot Merkle root of the batch
  event CommitPubRandBatch(
    uint32 indexed chainId,
    bytes indexed fpBtcPublicKey,
    uint64 fromBlock,
    uint64 toBlock,
    bytes32 merkleRoot
  );
}
