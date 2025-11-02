// send_proof.js
// Script to send a Merkle proof to a deployed contract using ethers.js

import { ethers } from "ethers";
import dotenv from "dotenv";
import fs from "fs";
import { execSync } from "child_process";
import crypto from "crypto";
dotenv.config();

// Load contract ABI and address (use only the ABI property from the artifact)
const artifact = JSON.parse(fs.readFileSync("../blockchain_layer/contracts/ProofOfReserves.json"));
const CONTRACT_ABI = artifact.abi;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;

// Prefer SMT root if present; fall back to MERKLE_ROOT (compat)
// We'll run the Python proof generator which writes `integration/merkle_proof.json`.
try {
  console.log("Generating proofs with Python generator...");
  execSync("python -u integration/merkle_proof_generator.py", { stdio: "inherit", env: process.env });
} catch (e) {
  console.error("Failed to run proof generator:", e.message);
}

const proofJsonPath = "integration/merkle_proof.json";
if (!fs.existsSync(proofJsonPath)) {
  console.error("Proof JSON not found at", proofJsonPath);
  process.exit(1);
}

const proofData = JSON.parse(fs.readFileSync(proofJsonPath, "utf8"));
// choose index from env or default to 0
const MERKLE_INDEX = parseInt(process.env.MERKLE_INDEX || "0", 10);
if (isNaN(MERKLE_INDEX) || MERKLE_INDEX < 0 || MERKLE_INDEX >= proofData.entries.length) {
  console.error("Invalid MERKLE_INDEX", process.env.MERKLE_INDEX);
  process.exit(1);
}

const entry = proofData.entries[MERKLE_INDEX];
const rootHex = proofData.smt_root;
const leafHex = entry.leaf; // hex without 0x
const smtProof = entry.smt_proof; // array of hex strings


// Helper to ensure 0x-prefixed 32-byte hex (bytes32)
function toBytes32Hex(hexStr) {
  if (!hexStr) return null;
  let s = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
  // if hex is longer than 64, truncate right-most (not ideal but keeps deterministic)
  if (s.length > 64) s = s.slice(0, 64);
  // pad left if shorter
  s = s.padStart(64, "0");
  return "0x" + s;
}

function sha256HexConcat(leftHex, rightHex) {
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  return crypto.createHash("sha256").update(Buffer.concat([left, right])).digest("hex");
}

function verifyLocalSMTProof(leafHex, proofArray, index, expectedRoot) {
  let h = leafHex;
  let idx = index;
  for (let i = 0; i < proofArray.length; i++) {
    const sib = proofArray[i];
    if (idx % 2 === 0) {
      h = sha256HexConcat(h, sib);
    } else {
      h = sha256HexConcat(sib, h);
    }
    idx = Math.floor(idx / 2);
  }
  return h === expectedRoot;
}

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
  // Verify proof locally before sending on-chain
  const localOk = verifyLocalSMTProof(leafHex, smtProof, MERKLE_INDEX, rootHex);
  if (!localOk) {
    console.error("Local SMT proof verification failed. Aborting send.");
    process.exit(1);
  }

  // Format the root into 32-byte hex and send it to the contract
  const formattedRoot = toBytes32Hex(rootHex);
  if (!formattedRoot) {
    console.error("No root available in environment (SMT_ROOT or MERKLE_ROOT). Aborting.");
    return;
  }

  console.log("Using root:", formattedRoot);
  const tx1 = await contract.updateRoot(formattedRoot);
  console.log("updateRoot transaction hash:", tx1.hash);
  await tx1.wait();
  console.log("Root updated on-chain.");

  // Prepare leaf and proof for on-chain verification (bytes32 array)
  const leafBytes = toBytes32Hex(leafHex);
  const proofBytes = smtProof.map((h) => toBytes32Hex(h));

  try {
    const onchainOk = await contract.verifySMTProof(leafBytes, proofBytes, MERKLE_INDEX);
    console.log("On-chain SMT proof verification result:", onchainOk);
  } catch (e) {
    console.error("Error calling on-chain verifySMTProof:", e.message);
  }

  // Call verifyProof with total reserves (from .env or hardcoded for now)
  const totalReserves = process.env.TOTAL_RESERVES;
  if (!totalReserves) {
    console.warn("TOTAL_RESERVES not set in .env. Skipping verifyProof call.");
    return;
  }
  const tx2 = await contract.verifyProof(totalReserves);
  console.log("verifyProof transaction hash:", tx2.hash);
  await tx2.wait();
  console.log("Proof verified (on-chain check completed).");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
