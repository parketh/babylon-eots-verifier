// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

// Schnorr signature library to prove possession of a Bitcoin private key when committing a batch
// of EOTS public randomness.
//
// The Schnorr signature scheme is defined as follows:
//
//   Signing
//    1. Given:
//       1. Priv-pub keypair (x, P)
//       2. Px denoting the x-coordinate of the public key P
//       3. Pyp denoting the parity of P (0 if y-coordinate is even, 1 if odd)
//       4. Generator G on secp256k1 curve with group order Q
//       5. keccak256 hash function H()
//       5. Hashed message m
//    2. Generate random nonce k and compute corresponding point on curve R = k * G
//    3. Compute Re = address(R), the lower 160 bits of H(Rx || Ry)
//    3. Compute the challenge, e = H(Px || Pyp || m || address(R))
//    4. Compute the signature, s = (k + e * x) % Q
//    5. Return signature (R, s)
//
//   Verification
//    1. Given inputs: Px, Pyp, s, m, address(R)
//    2. Recompute the challenge, e, as above
//    3. Verify that s * G = R + e * P
//
// This library implements an amended version of the protocol to allow efficient verification
// inside a Solidity contract using the `ecrecover` precompile, as documented here:
// https://hackmd.io/@nZ-twauPRISEa6G9zg3XRw/SyjJzSLt9/
//
// And implemented here:
// https://github.com/noot/schnorr-verify/blob/master/contracts/Schnorr.sol
//
//   Amended verification with `ecrecover`
//    1. Calculate:
//       1. sp = (Q - s * Px) % Q
//       2. ep = (Q - e * Px) % Q
//    2. Compute Z = ecrecover(sp, Pyp, Px, ep)
//    2. Calculate e' = H(Z || Pyp || Px || m)
//    3. Verify that e' == e

library SchnorrLib {
  // secp256k1 group order
  uint256 public constant Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
  uint256 public constant HALF_Q = (Q >> 1) + 1;

  error SignatureOverflow(bytes32 s);
  error InvalidSignatureLength(uint8 len);
  error InvalidPublicKey(bytes32 px);
  error EcRecoverInputZero();
  error EcRecoverOutputZero();

  /// @notice Verify a message signed using the Schnorr signature scheme
  /// @param parity Parity of the public key (27 if y-coordinate is even, 28 if odd)
  /// @param px x-coordinate of the public key
  /// @param message Hashed message
  /// @param e Challenge
  /// @param sig Schnorr signature
  function verify(uint8 parity, bytes32 px, bytes32 message, bytes32 e, bytes32 sig)
    public
    pure
    returns (bool)
  {
    // Validity checks
    if (uint256(px) >= HALF_Q) {
      revert InvalidPublicKey(px);
    }
    if (uint256(sig) >= Q) {
      revert SignatureOverflow(sig);
    }

    // Compute sp and ep
    bytes32 sp = bytes32(Q - mulmod(uint256(sig), uint256(px), Q));
    bytes32 ep = bytes32(Q - mulmod(uint256(e), uint256(px), Q));

    // The ecrecover precompile implementation checks that the `r` and `s`
    // inputs are non-zero (in this case, `px` and `ep`), thus we don't need to
    // check if they're zero
    if (sp == 0) {
      revert EcRecoverInputZero();
    }

    // Verify the signature
    address Z = ecrecover(sp, parity, px, ep);
    if (Z == address(0)) {
      revert EcRecoverOutputZero();
    }
    return e == keccak256(abi.encodePacked(Z, uint8(parity), px, message));
  }

  /// @notice Pack a Schnorr signature into a single bytearray
  /// @param parity Parity of the public key (0 if y-coordinate is even, 1 if odd)
  /// @param px x-coordinate of the public key
  /// @param message Hashed message
  /// @param e Challenge
  /// @param sig Schnorr signature
  function pack(uint8 parity, bytes32 px, bytes32 message, bytes32 e, bytes32 sig)
    public
    pure
    returns (bytes memory)
  {
    return abi.encode(parity, px, message, e, sig);
  }

  /// @notice Unpack a Schnorr signature into its components
  /// @param signature Schnorr signature
  function unpack(bytes memory signature)
    public
    pure
    returns (uint8 parity, bytes32 px, bytes32 message, bytes32 e, bytes32 sig)
  {
    // Encoding is padded so rounds to 160 bytes
    if (signature.length != 160) {
      revert InvalidSignatureLength(uint8(signature.length));
    }
    (parity, px, message, e, sig) =
      abi.decode(signature, (uint8, bytes32, bytes32, bytes32, bytes32));
  }
}
