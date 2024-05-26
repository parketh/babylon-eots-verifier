import BigInteger from "bigi";
import { arrayify } from "ethers/lib/utils";
import { ethers } from "ethers";
import { publicKeyCreate } from "secp256k1";
import { sign, verify } from "./Schnorr.utils";

// Setup
const privKey = BigInteger.fromHex(
  "e64149b2501f392fa458286acea16c6333700bb09497eab61a2a38865d9ef03f"
);
const privRand = BigInteger.fromHex(
  "18261145a75807f4543d82d61ca362ff85785fd3193c4ab72a848d2f70565b47"
);
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

// Sign message
const { R, s, e } = sign(
  Uint8Array.from(privKey.toBuffer(32)),
  Uint8Array.from(privRand.toBuffer(32)),
  hashedMsg
);

// Verify signature
const pubKey = publicKeyCreate(privKey.toBuffer(32));
const parity = pubKey[0] - 2 + 27;
const px = pubKey.slice(1, 33);
const isValid = verify(parity, px, hashedMsg, R, s, e);
if (isValid) {
  console.log("✅ Signature verified");
} else {
  throw new Error("Invalid signature");
}
