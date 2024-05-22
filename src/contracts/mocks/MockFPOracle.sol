// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../../interfaces/IFPOracle.sol";

contract MockFPOracle is IFPOracle {
  mapping(uint32 => uint64) public totalVotingPower;
  mapping(uint32 => mapping(string => uint64)) public votingPower;

  function getVotingPower(uint32 chainId) external view override returns (uint64) {
    return totalVotingPower[chainId];
  }

  function getVotingPower(uint32 chainId, string calldata fpBtcPublicKey)
    external
    view
    override
    returns (uint64)
  {
    return votingPower[chainId][fpBtcPublicKey];
  }

  function setVotingPower(uint32 chainId, uint64 power) public {
    totalVotingPower[chainId] = power;
  }

  function setVotingPower(uint32 chainId, string calldata fpBtcPublicKey, uint64 power) public {
    votingPower[chainId][fpBtcPublicKey] = power;
  }
}
