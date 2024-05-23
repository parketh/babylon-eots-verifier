// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

struct BatchKey {
  /// @notice Chain ID
  uint32 chainId;
  /// @notice Block number at which batch starts
  uint64 fromBlock;
  /// @notice Block number at which batch ends
  uint64 toBlock;
}

type BatchId is bytes32;

library BatchLib {
  /// @notice Serialize a batch key to a batch ID
  function toId(BatchKey memory batchKey) internal pure returns (BatchId batchId) {
    return
      BatchId.wrap(keccak256(abi.encode(batchKey.chainId, batchKey.fromBlock, batchKey.toBlock)));
  }
}
