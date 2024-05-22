// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { BatchId } from "../libraries/Batch.sol";

interface IEOTSVerifier {
  /// @notice Verify EOTS signature
  function verifyEots(uint32 chainId, string[] calldata fpBtcPublicKeys, bytes32[] calldata sigs)
    external;
}
