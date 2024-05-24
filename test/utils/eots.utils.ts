// JS implementation based on: https://github.com/babylonchain/babylon/blob/dev/crypto/eots

import secp256k1 from "secp256k1";
import crypto from "crypto";
import ecurve from "ecurve";
import BigInteger from "bigi";

const curve = ecurve.getCurveByName("secp256k1");

const BIP340Challenge = "BIP0340/challenge";

class EOTS {
  /**
   * Generates private key on secp256k1 curve.
   * @returns {BigInteger} privKey - Private key
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
   * @returns {ecurve.Point} pubKey - Public key as point on curve
   */
  getPublicKeyAsPoint(privKey: BigInteger): ecurve.Point {
    return curve.G.multiply(privKey);
  }

  /**
   * Derives public key from a private key.
   * @param {BigInteger} privKey - Private key
   * @returns {BigInteger} pubKey - Public key
   */
  getPublicKey(privKey: BigInteger): Buffer {
    const pubKeyPoint = this.getPublicKeyAsPoint(privKey);
    return this._serializeCompressed(pubKeyPoint);
  }

  /**
   * Signs a message using EOTS.
   * @param {BigInteger} privKey - Private key
   * @param {BigInteger} privRand - Private randomness
   * @param {string} msg - Message to sign
   * @returns {string} sig - Signature
   */
  sign(privKey: BigInteger, privRand: BigInteger, msg: string): string {
    const hash = this._hash(msg);
    return this._sign(privKey, privRand, hash);
  }

  _sign(privKey_: BigInteger, privRand: BigInteger, hash: Buffer): string {
    if (privKey_.equals(BigInteger.ZERO)) {
      throw new Error("Private key 0");
    }

    const pubKey = this.getPublicKeyAsPoint(privKey_);
    let privKey = privKey_;

    // If P.y is odd, negate the private key
    // Remove the first byte which indicates y parity
    let pubKeyBytes = this._serializeCompressed(pubKey);
    if (pubKeyBytes[0] === 0x03) {
      privKey = privKey.negate().mod(curve.n);
    }

    // R = k * G
    let k = privRand;
    const R = curve.G.multiply(k);

    // If R.y is odd, negate k
    if (!R.affineY.isEven()) {
      k = k.negate().mod(curve.n);
    }

    // e = H(R.x || P || M)
    const rBytes = R.affineX.toBuffer(32) as Buffer;
    let pBytes = this._serializeCompressed(pubKey);
    pBytes = Buffer.from(new Uint8Array(pBytes).slice(1));

    const commitment = this._taggedHash(BIP340Challenge, [
      rBytes,
      pBytes,
      hash,
    ]);

    const e = BigInteger.fromBuffer(commitment).mod(curve.n);

    // s = k + e * d mod n
    const sig = k.add(e.multiply(privKey)).mod(curve.n);

    return sig.toString(16);
  }

  verify(pubKey: ecurve.Point, pubRand: BigInteger, msg: string, sig: string) {
    const hash = this._hash(msg);
    return this._verify(pubKey, pubRand, hash, sig);
  }

  _verify(
    pubKey: ecurve.Point,
    pubRand: BigInteger,
    hash: Buffer,
    sig: string
  ) {
    curve.validate(pubKey);

    let pubKeyBytes = this._serializeCompressed(pubKey);
    if (pubKeyBytes[0] === 0x03) {
      pubKeyBytes[0] = 0x02;
    }

    const pubKeyEven: ecurve.Point = ecurve.Point.decodeFrom(
      curve,
      pubKeyBytes
    );

    const rBytes = pubRand.toBuffer(32) as Buffer;
    let pBytes = this._serializeCompressed(pubKeyEven);
    pBytes = Buffer.from(new Uint8Array(pBytes).slice(1));

    const commitment = this._taggedHash(BIP340Challenge, [
      rBytes,
      pBytes,
      hash,
    ]);

    // Negate e
    const e = BigInteger.fromBuffer(commitment).negate().mod(curve.n);

    // R = s * G - e * P
    const sG = curve.G.multiply(BigInteger.fromHex(sig));
    const eP = pubKeyEven.multiply(e);
    const R = sG.add(eP);

    if (
      R.affineX.equals(BigInteger.ZERO) &&
      R.affineY.equals(BigInteger.ZERO)
    ) {
      throw new Error("R not on curve");
    }

    if (!R.affineY.isEven()) {
      throw new Error("R.y is odd");
    }
    if (!R.affineX.equals(pubRand)) {
      throw new Error("R.x != pubRand");
    }
  }

  extract(
    pubKey: ecurve.Point,
    pubRand: BigInteger,
    msg1: string,
    sig1: string,
    msg2: string,
    sig2: string
  ): BigInteger {
    const hash1 = this._hash(msg1);
    const hash2 = this._hash(msg2);
    return this._extract(pubKey, pubRand, hash1, sig1, hash2, sig2);
  }

  _extract(
    pubKey: ecurve.Point,
    pubRand: BigInteger,
    hash1: Buffer,
    sig1: string,
    hash2: Buffer,
    sig2: string
  ): BigInteger {
    const rBytes = pubRand.toBuffer(32) as Buffer;
    let pBytes = this._serializeCompressed(pubKey);
    pBytes = Buffer.from(new Uint8Array(pBytes).slice(1));

    if (sig1 === sig2) {
      throw new Error("Signatures are the same");
    }

    const commitment1 = this._taggedHash(BIP340Challenge, [
      rBytes,
      pBytes,
      hash1,
    ]);
    const e1 = BigInteger.fromBuffer(commitment1).mod(curve.n);

    const commitment2 = this._taggedHash(BIP340Challenge, [
      rBytes,
      pBytes,
      hash2,
    ]);
    const e2 = BigInteger.fromBuffer(commitment2).mod(curve.n);

    const denom = e1.subtract(e2).mod(curve.n);
    let x = BigInteger.fromHex(sig1)
      .subtract(BigInteger.fromHex(sig2))
      .multiply(denom.modInverse(curve.n))
      .mod(curve.n);

    const pubKeyBytes = this._serializeCompressed(pubKey);
    if (pubKeyBytes[0] === 0x03) {
      x = x.negate().mod(curve.n);
    }

    const pubKeyCheck = curve.G.multiply(x);
    if (!pubKeyCheck.equals(pubKey)) {
      throw new Error("Extracted private key does not match public key");
    }

    return x;
  }

  _hash(msg: string): Buffer {
    return crypto.createHash("sha256").update(msg).digest();
  }

  _taggedHash(tag: string, msgs: Buffer[]): Buffer {
    const shaTag = crypto.createHash("sha256").update(tag).digest();
    const h = crypto.createHash("sha256");
    h.update(shaTag);
    h.update(shaTag);

    for (const msg of msgs) {
      h.update(msg);
    }
    return h.digest();
  }

  _serializeCompressed(pubKey: ecurve.Point): Buffer {
    const x = pubKey.affineX;
    const y = pubKey.affineY;
    const prefix = y.isEven() ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), x.toBuffer(32)]);
  }
}

export default EOTS;
