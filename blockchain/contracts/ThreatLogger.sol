// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ThreatLogger {

    // ── Owner & Access Control ────────────────────────────
    address public owner;
    mapping(address => bool) public authorizedReporters;

    // ── Threat Entry ──────────────────────────────────────
    struct ThreatEntry {
        uint256 id;
        string  alertHash;
        string  prediction;
        uint256 threatScore;
        string  riskLevel;
        string  fileName;
        string  topFeature;
        uint256 timestamp;
        address reporter;
        bool    quarantined;
        bool    resolved;
    }

    // ── Storage ───────────────────────────────────────────
    uint256 public totalThreats;
    uint256 public totalHighRisk;
    uint256 public totalResolved;

    ThreatEntry[] public threats;
    mapping(string  => bool)    public hashExists;
    mapping(string  => uint256) public hashToIndex;
    mapping(address => uint256) public reporterCount;
    mapping(string  => uint256[]) public predictionIndex;

    // ── Events ────────────────────────────────────────────
    event ThreatLogged(
        uint256 indexed id,
        string  indexed alertHash,
        string  prediction,
        uint256 threatScore,
        string  riskLevel,
        uint256 timestamp
    );
    event ThreatQuarantined(uint256 indexed id, string alertHash);
    event ThreatResolved(uint256 indexed id, string alertHash);
    event ReporterAuthorized(address indexed reporter);
    event ReporterRevoked(address indexed reporter);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    // ── Modifiers ─────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedReporters[msg.sender],
            "Not authorized"
        );
        _;
    }

    modifier validScore(uint256 score) {
        require(score <= 100, "Score must be 0-100");
        _;
    }

    modifier hashNotExists(string memory alertHash) {
        require(!hashExists[alertHash], "Hash already logged");
        _;
    }

    // ── Constructor ───────────────────────────────────────
    constructor() {
        owner = msg.sender;
        authorizedReporters[msg.sender] = true;
        emit ReporterAuthorized(msg.sender);
    }

    // ─────────────────────────────────────────────────────
    // CORE FUNCTIONS
    // ─────────────────────────────────────────────────────

    function logThreat(
        string memory alertHash,
        string memory prediction,
        uint256       threatScore,
        string memory riskLevel,
        string memory fileName,
        string memory topFeature
    )
        public
        onlyAuthorized
        validScore(threatScore)
        hashNotExists(alertHash)
        returns (uint256)
    {
        uint256 id = threats.length;

        threats.push(ThreatEntry({
            id:          id,
            alertHash:   alertHash,
            prediction:  prediction,
            threatScore: threatScore,
            riskLevel:   riskLevel,
            fileName:    fileName,
            topFeature:  topFeature,
            timestamp:   block.timestamp,
            reporter:    msg.sender,
            quarantined: threatScore > 70,
            resolved:    false
        }));

        hashToIndex[alertHash]  = id;
        hashExists[alertHash]   = true;
        reporterCount[msg.sender]++;
        totalThreats++;

        if (threatScore > 70) totalHighRisk++;

        predictionIndex[prediction].push(id);

        emit ThreatLogged(id, alertHash, prediction, threatScore, riskLevel, block.timestamp);

        if (threatScore > 70) {
            emit ThreatQuarantined(id, alertHash);
        }

        return id;
    }

    // ── Simple log (backward compatible) ─────────────────
    function logThreatSimple(
        string memory alertHash,
        string memory prediction,
        uint256       threatScore
    )
        public
        onlyAuthorized
        validScore(threatScore)
        hashNotExists(alertHash)
        returns (uint256)
    {
        return logThreat(
            alertHash, prediction, threatScore,
            threatScore > 70 ? "HIGH" : threatScore > 30 ? "MEDIUM" : "LOW",
            "unknown", "unknown"
        );
    }

    // ── Resolve a threat ──────────────────────────────────
    function resolveThreat(string memory alertHash) public onlyAuthorized {
        require(hashExists[alertHash], "Hash not found");
        uint256 idx = hashToIndex[alertHash];
        require(!threats[idx].resolved, "Already resolved");
        threats[idx].resolved = true;
        totalResolved++;
        emit ThreatResolved(idx, alertHash);
    }

    // ── Quarantine a threat manually ──────────────────────
    function quarantineThreat(string memory alertHash) public onlyAuthorized {
        require(hashExists[alertHash], "Hash not found");
        uint256 idx = hashToIndex[alertHash];
        threats[idx].quarantined = true;
        emit ThreatQuarantined(idx, alertHash);
    }

    // ─────────────────────────────────────────────────────
    // ACCESS CONTROL
    // ─────────────────────────────────────────────────────

    function authorizeReporter(address reporter) public onlyOwner {
        authorizedReporters[reporter] = true;
        emit ReporterAuthorized(reporter);
    }

    function revokeReporter(address reporter) public onlyOwner {
        require(reporter != owner, "Cannot revoke owner");
        authorizedReporters[reporter] = false;
        emit ReporterRevoked(reporter);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Invalid address");
        emit OwnershipTransferred(owner, newOwner);
        owner    = newOwner;
        authorizedReporters[newOwner] = true;
    }

    // ─────────────────────────────────────────────────────
    // READ FUNCTIONS
    // ─────────────────────────────────────────────────────

    function verifyHash(string memory alertHash)
        public view returns (bool)
    {
        return hashExists[alertHash];
    }

    function getThreatByHash(string memory alertHash)
        public view returns (ThreatEntry memory)
    {
        require(hashExists[alertHash], "Hash not found");
        return threats[hashToIndex[alertHash]];
    }

    function getThreatById(uint256 id)
        public view returns (ThreatEntry memory)
    {
        require(id < threats.length, "ID out of range");
        return threats[id];
    }

    function getTotalThreats() public view returns (uint256) {
        return threats.length;
    }

    function getStats() public view returns (
        uint256 total,
        uint256 highRisk,
        uint256 resolved,
        uint256 active
    ) {
        return (
            totalThreats,
            totalHighRisk,
            totalResolved,
            totalThreats - totalResolved
        );
    }

    function getRecentThreats(uint256 count)
        public view returns (ThreatEntry[] memory)
    {
        uint256 len    = threats.length;
        uint256 actual = count > len ? len : count;
        ThreatEntry[] memory result = new ThreatEntry[](actual);
        for (uint256 i = 0; i < actual; i++) {
            result[i] = threats[len - actual + i];
        }
        return result;
    }

    function getThreatsByPrediction(string memory prediction)
        public view returns (uint256[] memory)
    {
        return predictionIndex[prediction];
    }

    function getReporterStats(address reporter)
        public view returns (uint256)
    {
        return reporterCount[reporter];
    }

    function getAllThreats()
        public view returns (ThreatEntry[] memory)
    {
        return threats;
    }
}