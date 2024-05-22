// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

struct Leaf {
  /// @notice The block number at which the leaf was submitted
  uint64 blockNumber;
  /// @notice The committed public number
  bytes32 publicNumber;
}

library LeafLib {
  /// @notice Serialize leaf to encoded data
  function serialize(Leaf memory leaf) internal pure returns (bytes32 data) {
    return keccak256(abi.encode(leaf.blockNumber, leaf.publicNumber));
  }
}
