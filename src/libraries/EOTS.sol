// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

struct EOTSData {
  /// @param fpBtcPublicKey FP BTC public key
  bytes fpBtcPublicKey;
  /// @param pubRand FP committed pub rand
  bytes32 pubRand;
  /// @param merkleProof FP merkle proof to verify committed pub rand
  bytes32[] merkleProof;
  /// @param parity Parity of the public key
  uint8 parity;
  /// @param px x-coordinate of the public key
  bytes32 px;
  /// @param e Challenge
  bytes32 e;
  /// @param sig EOTS signature
  bytes32 sig;
}
