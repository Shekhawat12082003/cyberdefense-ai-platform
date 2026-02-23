const hre = require("hardhat");
const fs  = require("fs");
const path = require("path");

async function main() {
  console.log("╔══════════════════════════════════════════╗");
  console.log("║  🛡️  CyberDefense AI — Contract Deploy   ║");
  console.log("╚══════════════════════════════════════════╝\n");

  const network = hre.network.name;
  console.log("Network  :", network);

  // Get deployer
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer :", deployer.address);

  // Check balance
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  const balEth  = hre.ethers.utils.formatEther(balance);
  console.log("Balance  :", balEth, "tCORE");

  if (balance.eq(0)) {
    console.error("\n❌ Wallet is empty!");
    console.error("   Get free tCORE from: https://scan.test2.btcs.network/faucet");
    process.exit(1);
  }

  // Deploy
  console.log("\n⏳ Deploying ThreatLogger...");
  const ThreatLogger = await hre.ethers.getContractFactory("ThreatLogger");

  // Estimate gas
  const deployTx    = ThreatLogger.getDeployTransaction();
  const gasEstimate = await hre.ethers.provider.estimateGas(deployTx);
  console.log("Gas est. :", gasEstimate.toString());

  const contract = await ThreatLogger.deploy();
  console.log("TX hash  :", contract.deployTransaction.hash);
  console.log("⏳ Waiting for confirmation...");

  await contract.deployed();
  const address = contract.address;

  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║         ✅ DEPLOYMENT SUCCESSFUL          ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log("Address  :", address);
  console.log("Explorer :", `https://scan.test2.btcs.network/address/${address}`);

  // Verify contract works
  console.log("\n── Verifying contract functions ────────────");
  const [total, highRisk, resolved, active] = await contract.getStats();
  console.log("Total threats :", total.toString());
  console.log("High risk     :", highRisk.toString());
  console.log("Resolved      :", resolved.toString());
  console.log("Active        :", active.toString());

  const owner = await contract.owner();
  console.log("Owner         :", owner);

  // Test log one threat
  console.log("\n── Testing logThreatSimple ─────────────────");
  const testTx = await contract.logThreatSimple(
    "test_hash_deploy_verification_001",
    "Benign",
    10
  );
  await testTx.wait();
  console.log("✅ Test threat logged successfully!");

  const testEntry = await contract.getThreatByHash(
    "test_hash_deploy_verification_001"
  );
  console.log("Entry ID   :", testEntry.id.toString());
  console.log("Prediction :", testEntry.prediction);
  console.log("Score      :", testEntry.threatScore.toString());

  // ── Save ABI ───────────────────────────────────────────
  const artifactPath = path.join(
    __dirname,
    "..",
    "artifacts",
    "contracts",
    "ThreatLogger.sol",
    "ThreatLogger.json"
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const abi      = artifact.abi;

  // Save ABI in blockchain folder
  fs.writeFileSync(
    path.join(__dirname, "..", "ThreatLogger_ABI.json"),
    JSON.stringify(abi, null, 2)
  );
  console.log("\n📄 ThreatLogger_ABI.json saved in blockchain folder!");

  // Copy ABI to backend/blockchain
  const backendBlockchain = path.join(__dirname, "..", "..", "backend", "blockchain");
  if (fs.existsSync(backendBlockchain)) {
    fs.writeFileSync(
      path.join(backendBlockchain, "ThreatLogger_ABI.json"),
      JSON.stringify(abi, null, 2)
    );
    console.log("📄 ABI copied to backend/blockchain/");
  } else {
    fs.mkdirSync(backendBlockchain, { recursive: true });
    fs.writeFileSync(
      path.join(backendBlockchain, "ThreatLogger_ABI.json"),
      JSON.stringify(abi, null, 2)
    );
    console.log("📄 backend/blockchain/ created and ABI copied!");
  }

  // Copy ABI to backend/models
  const backendModels = path.join(__dirname, "..", "..", "backend", "models");
  if (fs.existsSync(backendModels)) {
    fs.writeFileSync(
      path.join(backendModels, "ThreatLogger_ABI.json"),
      JSON.stringify(abi, null, 2)
    );
    console.log("📄 ABI copied to backend/models/");
  }

  // ── Save deployment.json ───────────────────────────────
  const network2 = await hre.ethers.provider.getNetwork();
  const chainId  = network2.chainId.toString();

  const deploymentInfo = {
    network:         network,
    chainId:         chainId,
    contractAddress: address,
    deployer:        deployer.address,
    txHash:          contract.deployTransaction.hash,
    deployedAt:      new Date().toISOString(),
    rpc:             "https://rpc.test2.btcs.network",
    explorer:        `https://scan.test2.btcs.network/address/${address}`,
    txExplorer:      `https://scan.test2.btcs.network/tx/${contract.deployTransaction.hash}`,
    functions: [
      "logThreat(hash, prediction, score, riskLevel, fileName, topFeature)",
      "logThreatSimple(hash, prediction, score)",
      "verifyHash(hash) → bool",
      "getThreatByHash(hash) → ThreatEntry",
      "getThreatById(id) → ThreatEntry",
      "getStats() → (total, highRisk, resolved, active)",
      "getRecentThreats(count) → ThreatEntry[]",
      "resolveThreat(hash)",
      "quarantineThreat(hash)",
      "authorizeReporter(address)",
    ]
  };

  fs.writeFileSync(
    path.join(__dirname, "..", "deployment.json"),
    JSON.stringify(deploymentInfo, null, 2)
  );
  console.log("📄 deployment.json saved!");

  // ── Final summary ──────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║      🎯 ADD THESE TO BACKEND .env         ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log(`ETH_RPC_URL=https://rpc.test2.btcs.network`);
  console.log(`CONTRACT_ADDRESS=${address}`);
  console.log(`WALLET_PRIVATE_KEY=${process.env.PRIVATE_KEY}`);
  console.log(`CHAIN_ID=1114`);
  console.log("\n🔗 View contract on explorer:");
  console.log(`   https://scan.test2.btcs.network/address/${address}`);
}

main().catch((error) => {
  console.error("\n❌ Deployment failed:", error.message);
  process.exitCode = 1;
});