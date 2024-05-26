import { ethers } from "ethers";
import EOTS from "./EOTS.evm.utils";
import BigInteger from "bigi";

const eots = new EOTS();
const arrayify = ethers.utils.arrayify;

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
    "e64149b2501f392fa458286acea16c6333700bb09497eab61a2a38865d9ef03f"
  );
  const pubKey = eots.getPublicKeyAsPoint(privKey);
  const privRand = BigInteger.fromHex(
    "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
  );
  const pubRand = eots.getPublicKeyAsPoint(privRand);

  // Sign
  const hashedMsg = arrayify(
    ethers.utils.solidityKeccak256(
      ["uint32", "string", "uint64", "uint64", "bytes"],
      [
        1,
        "fp1",
        1,
        4,
        Buffer.from(
          "ba02a7da2f60d0c30b1c2ee6158f779b488276630391f346ca734f4f249eede3",
          "hex"
        ),
      ]
    )
  );
  const { e, s } = eots.sign(privKey, privRand, Buffer.from(hashedMsg));

  // Verify
  eots.verify(pubKey, pubRand, Buffer.from(hashedMsg), s);
  console.log({ m: "✅ Signature verified" });
};

const testExtractEOTS = () => {
  console.log("\nTest: testExtractEOTS");
  // Hard code key pair and randomness
  const privKey = BigInteger.fromHex(
    "e64149b2501f392fa458286acea16c6333700bb09497eab61a2a38865d9ef03f"
  );
  const pubKey = eots.getPublicKeyAsPoint(privKey);
  const privRand = BigInteger.fromHex(
    "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
  );
  const pubRand = eots.getPublicKeyAsPoint(privRand);

  // Sign 2 messages
  const msg1 = Buffer.from("hello world");
  const hashedMsg1 = Buffer.from(arrayify(ethers.utils.keccak256(msg1)));
  const { s: sig1 } = eots.sign(privKey, privRand, hashedMsg1);
  const msg2 = Buffer.from("goodbye");
  const hashedMsg2 = Buffer.from(arrayify(ethers.utils.keccak256(msg2)));
  const { s: sig2 } = eots.sign(privKey, privRand, hashedMsg2);

  // Extract EOTS
  const extractedPrivKey = eots.extract(
    pubKey,
    pubRand,
    hashedMsg1,
    sig1,
    hashedMsg2,
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
