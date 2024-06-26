// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

struct Leaf {
  /// @notice The block number at which the leaf was submitted
  uint64 blockNumber;
  /// @notice The committed public randomness
  bytes32 pubRand;
}

library LeafLib {
  /// @notice Serialize leaf to hash
  function hash(Leaf memory leaf) internal pure returns (bytes32) {
    return keccak256(abi.encode(leaf.blockNumber, leaf.pubRand));
  }
}
