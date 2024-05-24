import EOTS from "./eots.utils";
import BigInteger from "bigi";

const eots = new EOTS();

const testGenKeyPair = () => {
  console.log("\nTest: testGenKeyPair");
  const privKey = eots.genKey();
  const pubKey = eots.getPublicKey(privKey);
  console.log({
    m: "✅ Generated key pair",
    privKey: privKey.toString(16),
    pubKey: pubKey.toString("hex"),
  });
};

const testGenRandomness = () => {
  console.log("\nTest: testGenRandomness");
  const { privRand, pubRand } = eots.genRand();
  console.log({
    m: "✅ Generated randomness",
    privRand: privRand.toString(16),
    pubRand: pubRand.toString(16),
  });
};

const testSignAndVerify = () => {
  console.log("\nTest: testSignAndVerify");
  // Generate key pair and randomness
  const privKey = BigInteger.fromHex(
    "714481cca84598f1a3aaf42464d6892003ff3f12f438e09ae0adee83a60c2902"
  );
  const pubKey = eots.getPublicKeyAsPoint(privKey);
  const privRand = BigInteger.fromHex(
    "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
  );
  const pubRandKey = eots.getPublicKeyAsPoint(privRand);
  const pubRand = pubRandKey.affineX;

  // Sign
  const msg = Buffer.from("hello world");
  const { e, s } = eots.sign(privKey, privRand, msg);

  // Verify
  eots.verify(pubKey, pubRand, msg, s);
  console.log({ m: "✅ Signature verified" });
};

const testExtractEOTS = () => {
  console.log("\nTest: testExtractEOTS");
  // Hard code key pair and randomness
  const privKey = BigInteger.fromHex(
    "714481cca84598f1a3aaf42464d6892003ff3f12f438e09ae0adee83a60c2902"
  );
  const pubKey = eots.getPublicKeyAsPoint(privKey);
  const privRand = BigInteger.fromHex(
    "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
  );
  const pubRandKey = eots.getPublicKeyAsPoint(privRand);
  const pubRand = pubRandKey.affineX;

  // Sign 2 messages
  const msg1 = Buffer.from("hello world");
  const { s: sig1 } = eots.sign(privKey, privRand, msg1);
  const msg2 = Buffer.from("goodbye");
  const { s: sig2 } = eots.sign(privKey, privRand, msg2);

  // Extract EOTS
  const extractedPrivKey = eots.extract(
    pubKey,
    pubRand,
    msg1,
    sig1,
    msg2,
    sig2
  );
  if (extractedPrivKey.equals(privKey)) {
    console.log({
      m: "✅ EOTS extracted correctly",
      privKey: extractedPrivKey.toString(16),
    });
  } else {
    throw new Error("EOTS extraction failed");
  }
};

// testGenKeyPair();
// testGenRandomness();
// testSignAndVerify();
// testExtractEOTS();
