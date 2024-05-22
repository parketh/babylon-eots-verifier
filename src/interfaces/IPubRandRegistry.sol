// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { BatchId, BatchKey } from "../libraries/Batch.sol";

interface IPubRandRegistry {
  /// @notice Commit a batch of EOTS public randomness
  function commitPubRandBatch(
    BatchKey calldata batchKey,
    bytes calldata proofOfPossession,
    bytes32 merkleRoot
  ) external;
  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  function verifyPubRandAtBlock(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 publicNumber,
    bytes32[] calldata merkleProof
  ) external view returns (bool);

  /// @notice Event emitted when a new batch of EOTS public randomness is committed
  event CommitPubRandBatch(
    uint32 indexed chainId,
    string indexed fpBtcPublicKey,
    uint64 fromBlock,
    uint64 toBlock,
    bytes32 merkleRoot
  );
}
