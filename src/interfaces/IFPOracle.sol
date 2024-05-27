// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

interface IFPOracle {
  /// @notice Get current L2 block number
  /// @return blockNumber Current L2 block number
  function getL2BlockNumber() external view returns (uint64);

  /// @notice Get total voting power of all finality providers for given chain and block height
  /// @param chainId Chain ID
  /// @param atBlock Block height
  /// @return Total voting power
  function getVotingPower(uint32 chainId, uint64 atBlock) external view returns (uint64);

  /// @notice Get voting power of specific finality provider for given chain and block height
  /// @param chainId Chain ID
  /// @param atBlock Block height
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @return Voting power of the finality provider
  function getVotingPowerFor(uint32 chainId, uint64 atBlock, bytes calldata fpBtcPublicKey)
    external
    view
    returns (uint64);
}
