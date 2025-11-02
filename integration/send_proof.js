// send_proof.js
// Script to send a Merkle proof to a deployed contract using ethers.js

import { ethers } from "ethers";
import dotenv from "dotenv";
import fs from "fs";
dotenv.config();

// Load contract ABI and address (use only the ABI property from the artifact)
const artifact = JSON.parse(fs.readFileSync("../blockchain_layer/contracts/ProofOfReserves.json"));
const CONTRACT_ABI = artifact.abi;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;

// Prefer SMT root if present; fall back to MERKLE_ROOT (compat)
let rootHex = process.env.SMT_ROOT || process.env.MERKLE_ROOT || process.env.MERKLE_VERKLE_ROOT;
// Proof may be stored as JSON string in env or external file; we just log it here
const proof = process.env.MERKLE_PROOF ? JSON.parse(process.env.MERKLE_PROOF) : [];

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

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
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
