// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

interface IPubRandRegistry {
  /// @notice Commit a batch of EOTS public randomness
  /// @param epoch Epoch number
  /// @param fpBtcPublicKey Finality provider btc public key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param merkleRoot Merkle root of the batch
  function commitPubRandBatch(
    uint64 epoch,
    bytes calldata fpBtcPublicKey,
    bytes calldata proofOfPossession,
    bytes32 merkleRoot
  ) external;

  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  /// @param epoch Epoch number
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @param atBlock Block number at which the public randomness was committed
  /// @param pubRand Committed public number
  /// @param merkleProof Merkle proof of the public number
  /// @return isValid Whether the public number is valid
  function verifyPubRandAtBlock(
    uint64 epoch,
    bytes calldata fpBtcPublicKey,
    uint64 atBlock,
    bytes32 pubRand,
    bytes32[] calldata merkleProof
  ) external view returns (bool);

  /// @notice Event emitted when a new batch of EOTS public randomness is committed
  /// @param epoch Epoch number
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @param merkleRoot Merkle root of the batch
  event CommitPubRandBatch(uint64 indexed epoch, bytes indexed fpBtcPublicKey, bytes32 merkleRoot);
}
