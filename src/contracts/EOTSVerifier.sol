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

contract EOTSVerifier is IPubRandRegistry {
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
  /// @notice This fn is called by a client or rollup contract to provide fast finality
  /// @param batchKey Batch key
  /// @param atBlock Block height to verify
  /// @param outputRoot Output root of the block
  /// @param fpBtcPublicKeys FP BTC public keys
  /// @param pubRands FP committed pub rands
  /// @param merkleProofs FP merkle proofs to verify committed pub rands
  /// @param signatures FP EOTS signatures
  function verifyEots(
    BatchKey calldata batchKey,
    uint64 atBlock,
    bytes32 outputRoot,
    bytes[] calldata fpBtcPublicKeys,
    bytes32[] calldata pubRands,
    bytes32[][] calldata merkleProofs,
    bytes[] calldata signatures
  ) external {
    // Validity checks
    // Check arrays are of equal length
    // Check block is in the past
    // Check block is within the batch range

    // Loop through pub rands and check against commitments

    // Get voting power (VP) of each finality provider, and check they sum to >2/3 total VP

    // Verify EOTS signatures
  }
}
