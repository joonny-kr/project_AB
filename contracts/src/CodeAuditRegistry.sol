// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CodeAuditRegistry {
    enum LicenseRisk { None, Low, Medium, High }
    struct Audit {
        bytes32 commitHash;
        string  reportCID;       // ipfs://<CID>
        uint8   securityScore;   // 0~100
        LicenseRisk licenseRisk;
        bool    aiGenerated;
        address submitter;
        uint64  analyzedAt;
    }
    mapping(bytes32 => Audit) public auditByCommit;
    event AuditRecorded(bytes32 indexed commitHash, string reportCID, uint8 securityScore, LicenseRisk risk, bool aiGenerated, address submitter, uint64 analyzedAt);

    function recordAudit(
        bytes32 commitHash,
        string calldata reportCID,
        uint8 securityScore,
        LicenseRisk risk,
        bool aiGenerated,
        uint64 analyzedAt
    ) external {
        require(auditByCommit[commitHash].analyzedAt == 0, "Already recorded");
        auditByCommit[commitHash] = Audit(commitHash, reportCID, securityScore, risk, aiGenerated, msg.sender, analyzedAt);
        emit AuditRecorded(commitHash, reportCID, securityScore, risk, aiGenerated, msg.sender, analyzedAt);
    }
}
