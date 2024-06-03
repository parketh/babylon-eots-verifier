// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "src/interfaces/IFPOracle.sol";

contract MockFPOracle is IFPOracle {
  uint32 public l2BlockNumber;
  mapping(uint32 => mapping(uint64 => uint64)) public totalVotingPower;
  mapping(uint32 => mapping(uint64 => mapping(bytes => uint64))) public votingPower;

  function getL2BlockNumber() external view override returns (uint64) {
    return l2BlockNumber;
  }

  function getVotingPower(uint32 chainId, uint64 atBlock) external view returns (uint64) {
    return totalVotingPower[chainId][atBlock];
  }

  function getVotingPowerFor(uint32 chainId, uint64 atBlock, bytes calldata fpBtcPublicKey)
    external
    view
    returns (uint64)
  {
    return votingPower[chainId][atBlock][fpBtcPublicKey];
  }

  function setL2BlockNumber(uint32 blockNumber) public {
    l2BlockNumber = blockNumber;
  }

  function setVotingPower(uint32 chainId, uint64 atBlock, uint64 power) public {
    totalVotingPower[chainId][atBlock] = power;
  }

  function setVotingPowerFor(
    uint32 chainId,
    uint64 atBlock,
    bytes calldata fpBtcPublicKey,
    uint64 power
  ) public {
    votingPower[chainId][atBlock][fpBtcPublicKey] = power;
  }
}
