# project_AB(On-chain AI Code Audit & Provenance Stamp)

**Project Overview**  
A system that securely and transparently records the proportion of AI-generated code and security analysis results by storing analysis reports on IPFS and registering the corresponding CID and Git commit information on the blockchain.

**Core Workflow**
- Extract the current Git commit and project tree hashes in a local or CI environment.
- Use an analyzer to calculate the AI-generated code ratio and security score, then save the results as a JSON report.
- Upload this JSON report to IPFS and obtain its CID.
- Record the CID and hash information on-chain via a smart contract to ensure immutability.
- Anyone can later re-hash the code from the same commit and compare it with the on-chain record to verify integrity.

**Tech Stack (Example)**
- **Rust CLI**: Hash extraction and JSON report generation  
- **Node.js / Rust API Server**: Analysis requests, IPFS uploads, smart contract calls  
- **Solidity Smart Contract**: CID and hash storage, verification functions  
- **Storacha**: IPFS-based pinning service for reliable CID storage  

**Project Goal**
- Ensure transparency and accountability for AI-generated code by making its provenance and security status permanently verifiable  
- Build a decentralized certification and record-keeping infrastructure using blockchain and IPFS without relying on centralized systems
