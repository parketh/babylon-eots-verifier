// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

interface IFPOracle {
  /// @notice Get total voting power amongst all finality providers of a given chain
  function getVotingPower(uint32 chainId) external view returns (uint64);
  /// @notice Get the voting power of a specific finality provider
  function getVotingPower(uint32 chainId, string calldata fpBtcPublicKey) external view returns (uint64);
}
