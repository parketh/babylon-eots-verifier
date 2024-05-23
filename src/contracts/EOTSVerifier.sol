// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
// import "forge-std/console.sol";
import { IEOTSVerifier } from "../interfaces/IEOTSVerifier.sol";
import { IPubRandRegistry } from "../interfaces/IPubRandRegistry.sol";
import { IFPOracle } from "../interfaces/IFPOracle.sol";
import "../libraries/Batch.sol";
import "../libraries/Leaf.sol";
import "../libraries/Schnorr.sol";

error InvalidBlockRange();
error InvalidProofOfPossession();
error MessageMismatch();
error InvalidMerkleProof();
error PubRandMismatch();
error InputLengthMismatch();

contract EOTSVerifier is IPubRandRegistry, IEOTSVerifier {
  using BatchLib for BatchKey;
  using LeafLib for Leaf;
  using SchnorrLib for bytes;

  mapping(BatchId => mapping(bytes => bytes32)) public merkleRoots;
  mapping(BatchId => mapping(bytes => uint64)) public lastCommittedBlocks;
  IFPOracle public immutable fpOracle;

  constructor(IFPOracle _fpOracle) {
    fpOracle = _fpOracle;
  }

  /// @notice Commit a batch of EOTS public randomness
  /// @param batchKey Batch key
  /// @param fpBtcPublicKey Finality provider btc public key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param merkleRoot Merkle root of the batch
  function commitPubRandBatch(
    BatchKey calldata batchKey,
    bytes calldata fpBtcPublicKey,
    bytes calldata proofOfPossession,
    bytes32 merkleRoot
  ) external {
    // Run validity checks
    BatchId batchId = batchKey.toId();
    uint64 lastCommittedBlock = lastCommittedBlocks[batchId][fpBtcPublicKey];
    if (
      batchKey.fromBlock >= batchKey.toBlock || batchKey.fromBlock < block.number
        || batchKey.fromBlock <= lastCommittedBlock
    ) {
      revert InvalidBlockRange();
    }

    // Verify proof of possession of fp btc key
    _verifyProofOfPossession(proofOfPossession, batchKey, fpBtcPublicKey, merkleRoot);

    // Write merkle root to storage
    merkleRoots[batchId][fpBtcPublicKey] = merkleRoot;

    // Emit event
    emit CommitPubRandBatch(
      batchKey.chainId, fpBtcPublicKey, batchKey.fromBlock, batchKey.toBlock, merkleRoot
    );
  }

  /// @notice Verify caller's proof of possession of finality provider btc key
  /// @param proofOfPossession Signature to prove possession of finality provider btc key
  /// @param batchKey Signed message
  /// @param merkleRoot Merkle root of the batch
  function _verifyProofOfPossession(
    bytes memory proofOfPossession,
    BatchKey memory batchKey,
    bytes memory fpBtcPublicKey,
    bytes32 merkleRoot
  ) internal pure {
    // Unpack proof of possession
    (uint8 pyp, bytes32 px, bytes32 m, bytes32 e, bytes32 s) = proofOfPossession.unpack();

    // Hash calldata and check it matches the signed message
    // TODO: confirm format of the signed message
    // For now, we use keccak(chainId, fpBtcPublicKey, fromBlock, toBlock, merkleRoot)
    bytes32 hashedMsg = keccak256(
      abi.encodePacked(
        batchKey.chainId, fpBtcPublicKey, batchKey.fromBlock, batchKey.toBlock, merkleRoot
      )
    );
    if (hashedMsg != m) {
      revert MessageMismatch();
    }

    // Verify proof of possession
    if (!SchnorrLib.verify(pyp, px, m, e, s)) {
      revert InvalidProofOfPossession();
    }
  }

  /// @notice Verify EOTS public randomness committed by a finality provider at given block height
  /// @param batchKey Batch key
  /// @param fpBtcPublicKey Finality provider BTC public key
  /// @param atBlock Block number at which the public randomness was committed
  /// @param pubRand Committed public randomness
  /// @param merkleProof Merkle proof of the public number
  /// @return isValid Whether the public number is valid
  function verifyPubRandAtBlock(
    BatchKey calldata batchKey,
    bytes calldata fpBtcPublicKey,
    uint64 atBlock,
    bytes32 pubRand,
    bytes32[] calldata merkleProof
  ) public view returns (bool) {
    // Retrieve merkle root from storage
    BatchId batchId = batchKey.toId();
    bytes32 merkleRoot = merkleRoots[batchId][fpBtcPublicKey];

    // Hash calldata to get leaf
    Leaf memory leaf = Leaf(atBlock, pubRand);
    bytes32 hashedLeaf = leaf.hash();

    // Verify merkle proof
    return MerkleProof.verify(merkleProof, merkleRoot, hashedLeaf);
  }

  /// @notice Verify EOTS signatures from finality providers at given block height
  /// @notice Called by a client or rollup contract to provide fast finality
  /// @param batchKey Batch key
  /// @param atBlock Block height to verify
  /// @param outputRoot Output root of the block
  /// @param fpBtcPublicKeys FP BTC public keys
  /// @param pubRands FP committed pub rands
  /// @param merkleProofs FP merkle proofs to verify committed pub rands
  /// @param signatures FP EOTS signatures
  /// @return isFinal Whether the block is final
  function verifyEots(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 outputRoot,
    bytes[] calldata fpBtcPublicKeys,
    bytes32[] calldata pubRands,
    bytes32[][] calldata merkleProofs,
    bytes[] calldata signatures
  ) external view returns (bool) {
    // Perform validity checks
    if (
      fpBtcPublicKeys.length != pubRands.length || fpBtcPublicKeys.length != merkleProofs.length
        || fpBtcPublicKeys.length != signatures.length
    ) {
      revert InputLengthMismatch();
    }
    if (atBlock < batchKey.fromBlock || atBlock > batchKey.toBlock || atBlock > block.number) {
      revert InvalidBlockRange();
    }

    // Init voting power (VP) vars
    // We can consider the block final once signers comprising 2/3 of total VP have signed off
    uint64 thresholdVotingPower = fpOracle.getVotingPower(batchKey.chainId, atBlock) * 2 / 3;
    uint64 sumVotingPower = 0;

    // Loop through signers and:
    //  1. Check pub rands against batch commitments
    //  2. Check challenge matches committed pub rands, e = H(Px || Pyp || m || Re)
    //  3. Verify EOTS signatures
    for (uint256 i = 0; i < fpBtcPublicKeys.length; i++) {
      // Unpack signature and check message
      // TODO: confirm format of the signed message
      (uint8 pyp, bytes32 px,, bytes32 e, bytes32 s) = signatures[i].unpack();
      // Verify pub rand and merkle proof
      // We expect m = outputRoot so use it in place of m to perform the check in the same step
      bytes32 expE = keccak256(abi.encodePacked(px, pyp, outputRoot, pubRands[i]));
      if (
        e != expE
          || !verifyPubRandAtBlock(batchKey, fpBtcPublicKeys[i], atBlock, pubRands[i], merkleProofs[i])
      ) {
        revert PubRandMismatch();
      }

      // Verify EOTS signature of finality provider
      // If verified, get voting power (VP) and add to sum
      // As above, we use outputRout in place of m
      if (SchnorrLib.verify(pyp, px, outputRoot, e, s)) {
        sumVotingPower += fpOracle.getVotingPower(batchKey.chainId, atBlock, fpBtcPublicKeys[i]);
      }

      // To save gas, break early if we have enough voting power
      if (sumVotingPower >= thresholdVotingPower) {
        return true;
      }
    }

    return false;
  }
}
