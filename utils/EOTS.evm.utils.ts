// EOTS implementation modified for efficient verification on the EVM. In particular, we amend the
// scheme to make it compatible with the `ecrecover` precompile and `keccak256` hash function.
//
// Compared to the Go reference implementation at:
// https://github.com/babylonchain/babylon/blob/dev/crypto/eots
//
// This implementation makes the following changes:
//  1. Use address(R) in place of R by hashing the uncompressed pubKey and taking the last 20 bytes
//  2. Use keccak256(address(R) || pubkey parity || pubKey.X || m) in place of tagged hash scheme
//  3. Passes in the hashed message directly rather than re-hashing with SHA-256
//  4. Remove logic for correcting private key for parity of public key

import secp256k1 from "secp256k1";
import crypto from "crypto";
import ecurve from "ecurve";
import BigInteger from "bigi";
import { ethers } from "ethers";
import { bytesToHex, ecrecover, hexToBytes } from "@ethereumjs/util";

const curve = ecurve.getCurveByName("secp256k1");
const arrayify = ethers.utils.arrayify;

const Q = BigInteger.fromHex(
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
const HALF_Q = BigInteger.fromHex(
  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
);

class EOTS {
  /**
   * Generates private key on secp256k1 curve.
   * @returns {BigInteger} Private key
   */
  genKey(): BigInteger {
    let privKey: Buffer;
    do {
      privKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privKey));
    return BigInteger.fromBuffer(privKey);
  }

  /**
   * Generates private and public randomness for EOTS signatures.
   * @returns {{ privRand: BigInteger, pubRand: BigInteger }} - Private and public randomness
   */
  genRand(): { privRand: BigInteger; pubRand: BigInteger } {
    const privKey = this.genKey();
    const pubKey = this.getPublicKeyAsPoint(privKey);
    const pubRand = pubKey.affineX;
    return { privRand: privKey, pubRand };
  }

  /**
   * Derives public key from a private key.
   * @param {BigInteger} privKey - Private key
   * @returns {ecurve.Point} Public key as point on curve
   */
  getPublicKeyAsPoint(privKey: BigInteger): ecurve.Point {
    return curve.G.multiply(privKey);
  }

  /**
   * Derives public key from a private key.
   * @param {BigInteger} privKey - Private key
   * @returns {Buffer} Public key
   */
  getPublicKey(privKey: BigInteger): Buffer {
    const pubKeyPoint = this.getPublicKeyAsPoint(privKey);
    return this._serializeCompressed(pubKeyPoint);
  }

  /**
   * Get parity of public key.
   * @param {ecurve.Point} pubKey - Public key as point on curve
   * @returns {number} parity - Parity of public key
   */
  getParity(pubKey: ecurve.Point): number {
    const pubKeyBytes = this._serializeCompressed(pubKey);
    return pubKeyBytes[0] - 2 + 27;
  }

  /**
   * Signs a message using EOTS.
   * @param {BigInteger} privKey - Private key
   * @param {BigInteger} privRand - Private randomness
   * @param {Buffer} msg - Hashed message
   * @returns {{ e: BigInteger; s: BigInteger }} - Commitment and signature
   */
  sign(
    privKey_: BigInteger,
    privRand: BigInteger,
    msg: Buffer
  ): { e: BigInteger; s: BigInteger } {
    if (privKey_.equals(BigInteger.ZERO)) {
      throw new Error("Private key 0");
    }

    const pubKey = this.getPublicKeyAsPoint(privKey_);
    let privKey = privKey_;

    // If P.y is odd, negate the private key
    // Remove the first byte which indicates y parity
    let pubKeyBytes = this._serializeCompressed(pubKey);
    // if (pubKeyBytes[0] === 0x03) {
    //   privKey = privKey.negate().mod(curve.n);
    // }

    // R = k * G
    let k = privRand;
    const R = curve.G.multiply(k);

    // If R.y is odd, negate k
    // if (!R.affineY.isEven()) {
    //   k = k.negate().mod(curve.n);
    // }

    // e = H(R.x || P || M)
    const e = this._computeCommitment(R, pubKey, msg);

    // s = k + e * d mod n
    const s = k.add(e.multiply(privKey)).mod(curve.n);

    return { e, s };
  }

  /**
   * Verify a message signed using EOTS.
   * @param {ecurve.Point} pubKey - Public key
   * @param {ecurve.Point} pubRand - Public randomness
   * @param {Buffer} msg - Hashed message
   * @param {BigInteger} sig - Signature
   */
  verify(
    pubKey: ecurve.Point,
    pubRand: ecurve.Point,
    msg: Buffer,
    sig: BigInteger
  ) {
    curve.validate(pubKey);

    let pubKeyBytes = this._serializeCompressed(pubKey);
    // if (pubKeyBytes[0] === 0x03) {
    //   pubKeyBytes[0] = 0x02;
    // }

    const pubKeyEven: ecurve.Point = ecurve.Point.decodeFrom(
      curve,
      pubKeyBytes
    );

    // Calculate commitment, parity, and pubKeyX.
    const e = this._computeCommitment(pubRand, pubKeyEven, msg);
    const parity = this.getParity(pubKeyEven);
    const pubKeyX = pubKeyEven.affineX.toBuffer(32) as Buffer;

    // Compute sp and ep
    const sp = Q.subtract(sig.multiply(BigInteger.fromBuffer(pubKeyX)).mod(Q));
    const ep = Q.subtract(e.multiply(BigInteger.fromBuffer(pubKeyX)).mod(Q));
    if (sp.equals(BigInteger.ZERO)) {
      throw new Error("sp is zero");
    }

    // Recover address
    const recoveredPublicKey = ecrecover(
      sp.toBuffer(32),
      BigInt(parity),
      pubKeyX,
      ep.toBuffer(32)
    );
    const recoveredAddress = bytesToHex(
      hexToBytes(ethers.utils.keccak256(recoveredPublicKey)).slice(12, 32)
    );
    const ePrime = this._enforcePrefix(
      ethers.utils.solidityKeccak256(
        ["address", "uint8", "bytes32", "bytes32"],
        [recoveredAddress, parity, Buffer.from(pubKeyX), msg]
      )
    );

    if (
      pubRand.affineX.equals(BigInteger.ZERO) &&
      pubRand.affineY.equals(BigInteger.ZERO)
    ) {
      throw new Error("R not on curve");
    }

    if (!pubRand.affineY.isEven()) {
      throw new Error("R.y is odd");
    }
    if (this._enforcePrefix(e.toString(16)) !== ePrime) {
      throw new Error("Invalid signature");
    }
  }

  /**
   * Extract private key from two EOTS signatures.
   * @param {ecurve.Point} pubKey - Public key
   * @param {ecurve.Point} pubRand - Public randomness
   * @param {Buffer} msg1 - First hashed message
   * @param {BigInteger} sig1 - First signature
   * @param {Buffer} msg2 - Second hashed message
   * @param {BigInteger} sig2 - Second signature
   * @returns {BigInteger} Extracted private key
   */
  extract(
    pubKey: ecurve.Point,
    pubRand: ecurve.Point,
    msg1: Buffer,
    sig1: BigInteger,
    msg2: Buffer,
    sig2: BigInteger
  ): BigInteger {
    if (sig1 === sig2) {
      throw new Error("Signatures are the same");
    }

    const e1 = this._computeCommitment(pubRand, pubKey, msg1);
    const e2 = this._computeCommitment(pubRand, pubKey, msg2);

    const denom = e1.subtract(e2).mod(curve.n);
    let x = sig1
      .subtract(sig2)
      .multiply(denom.modInverse(curve.n))
      .mod(curve.n);

    const pubKeyBytes = this._serializeCompressed(pubKey);
    // if (pubKeyBytes[0] === 0x03) {
    //   x = x.negate().mod(curve.n);
    // }

    const pubKeyCheck = curve.G.multiply(x);
    if (!pubKeyCheck.equals(pubKey)) {
      throw new Error("Extracted private key does not match public key");
    }

    return x;
  }

  /**
   * Internal function to compute the commitment hash.
   * @param {ecurve.Point} pubRand - Public randomness
   * @param {ecurve.Point} pubKey - Public key
   * @param {Buffer} msg - Message
   * @returns {BigInteger} Commitment hash
   */
  _computeCommitment(
    pubRand: ecurve.Point,
    pubKey: ecurve.Point,
    msg: Buffer
  ): BigInteger {
    const addressR = this._pubKeyToAddress(pubRand);
    let pBytes = this._serializeCompressed(pubKey);
    const parity = pBytes[0] + 27 - 2;
    pBytes = Buffer.from(new Uint8Array(pBytes).slice(1, 33));
    const commitment = arrayify(
      ethers.utils.solidityKeccak256(
        ["address", "uint8", "bytes32", "bytes32"],
        [addressR, parity, pBytes, msg]
      )
    );
    return BigInteger.fromBuffer(commitment).mod(curve.n);
  }

  /**
   * Internal function to convert an uncompressed public key to an EVM address.
   * @param {ecurve.Point} pubKey - Public key as point on curve
   * @returns {Uint8Array} EVM address
   */
  _pubKeyToAddress(pubKey: ecurve.Point): Uint8Array {
    const uncompressed = Uint8Array.from(pubKey.getEncoded(false));
    return arrayify(ethers.utils.keccak256(uncompressed.slice(1, 65))).slice(
      12,
      32
    );
  }

  /**
   * Internal function to add the 0x prefix to an address if it is missing.
   * @param {string} addr - Address
   * @returns {string} Address with 0x prefix
   */
  _enforcePrefix = (addr: string): string => {
    let address = addr.toLowerCase();
    if (addr.startsWith("0x")) {
      address = addr.slice(2);
    }
    // Pad to 64 characters
    if (address.length < 64) {
      address = "0".repeat(64 - address.length) + address;
    }
    return "0x" + address;
  };

  /**
   * Internal function to serialize a public key point to compressed format.
   * @param {ecurve.Point} pubKey - Public key as point on curve
   * @returns {Buffer} Public key in compressed format
   */
  _serializeCompressed(pubKey: ecurve.Point): Buffer {
    const x = pubKey.affineX;
    const y = pubKey.affineY;
    const prefix = y.isEven() ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), x.toBuffer(32)]);
  }
}

export default EOTS;
