// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../../interfaces/IFPOracle.sol";

contract MockFPOracle is IFPOracle {
  mapping(uint32 => mapping(uint64 => uint64)) public totalVotingPower;
  mapping(uint32 => mapping(uint64 => mapping(bytes => uint64))) public votingPower;

  function getVotingPower(uint32 chainId, uint64 atBlock) external view returns (uint64) {
    return totalVotingPower[chainId][atBlock];
  }

  function getVotingPower(uint32 chainId, uint64 atBlock, bytes calldata fpBtcPublicKey)
    external
    view
    returns (uint64)
  {
    return votingPower[chainId][atBlock][fpBtcPublicKey];
  }

  function setVotingPower(uint32 chainId, uint64 atBlock, uint64 power) public {
    totalVotingPower[chainId][atBlock] = power;
  }

  function setVotingPower(
    uint32 chainId,
    uint64 atBlock,
    bytes calldata fpBtcPublicKey,
    uint64 power
  ) public {
    votingPower[chainId][atBlock][fpBtcPublicKey] = power;
  }
}
