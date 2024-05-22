// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "src/libraries/Schnorr.sol";

contract MockSchnorr {
  /// @notice Verify a message signed using the Schnorr signature scheme
  /// @param parity Parity of the public key (0 if y-coordinate is even, 1 if odd)
  /// @param px x-coordinate of the public key
  /// @param message Hashed message
  /// @param e Challenge
  /// @param sig Schnorr signature
  function verify(uint8 parity, bytes32 px, bytes32 message, bytes32 e, bytes32 sig)
    public
    pure
    returns (bool)
  {
    return SchnorrLib.verify(parity, px, message, e, sig);
  }
}
