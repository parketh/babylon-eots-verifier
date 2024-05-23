// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { BatchKey } from "../libraries/Batch.sol";
import { EOTSData } from "../libraries/EOTS.sol";

interface IEOTSVerifier {
  /// @notice Verify EOTS signatures from finality providers at given block height
  /// @notice This fn is called by a client or rollup contract to provide fast finality
  /// @param batchKey Batch key
  /// @param atBlock Block height to verify
  /// @param outputRoot Output root of the block
  /// @param data EOTS data
  /// @return isFinal Whether the block is final
  function verifyEots(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 outputRoot,
    EOTSData[] calldata data
  ) external returns (bool);
}
