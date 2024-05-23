// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

struct EOTSData {
  /// @param fpBtcPublicKeys FP BTC public keys
  bytes fpBtcPublicKey;
  /// @param pubRands FP committed pub rands
  bytes32 pubRand;
  /// @param merkleProofs FP merkle proofs to verify committed pub rands
  bytes32[] merkleProof;
  /// @param signatures FP EOTS signatures
  bytes signature;
}
