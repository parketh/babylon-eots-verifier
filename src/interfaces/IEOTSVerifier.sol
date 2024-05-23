// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { BatchKey } from "../libraries/Batch.sol";

interface IEOTSVerifier {
  /// @notice Verify EOTS signatures from finality providers at given block height
  /// @notice This fn is called by a client or rollup contract to provide fast finality
  /// @param batchKey Batch key
  /// @param atBlock Block height to verify
  /// @param outputRoot Output root of the block
  /// @param fpBtcPublicKeys FP BTC public keys
  /// @param pubRands FP committed pub rands
  /// @param signatures FP EOTS signatures
  function verifyEots(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 outputRoot,
    bytes[] calldata fpBtcPublicKeys,
    bytes32[] calldata pubRands,
    bytes[] calldata signatures
  ) external;
}
