use anyhow::*;
use clap::Parser;
use chrono::Utc;
use dotenvy::dotenv;
use ethers::prelude::*;
use ethers::utils::keccak256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "ai_code_audit")]
struct Args {
    /// 해시 계산 루트
    #[arg(long, default_value = ".")]
    root: String,

    /// Base Sepolia RPC
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// 배포된 컨트랙트 주소
    #[arg(long, env = "CONTRACT_ADDR")]
    contract_addr: String,

    /// 트랜잭션 서명 키(테스트넷)
    #[arg(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// Storacha CLI 사용 여부 (true: storacha put)
    #[arg(long, env = "USE_STORACHA_CLI", default_value_t = true)]
    use_storacha_cli: bool,

    /// HTTP Bridge 사용 시: 엔드포인트 (예: https://up.web3.storage/upload)
    #[arg(long, env = "STORACHA_BRIDGE_ENDPOINT", default_value = "")]
    bridge_endpoint: String,
    /// HTTP Bridge 사용 시: Authorization 헤더 값
    #[arg(long, env = "STORACHA_AUTH", default_value = "")]
    bridge_auth: String,
    /// HTTP Bridge 사용 시: X-Auth-Secret 헤더 값(필요한 경우)
    #[arg(long, env = "STORACHA_SECRET", default_value = "")]
    bridge_secret: String,

    /// AI 생성 코드 포함 플래그
    #[arg(long, env = "AI_GENERATED", default_value_t = true)]
    ai_generated: bool,

    /// 표시용 프로젝트 식별자
    #[arg(long, env = "PROJECT", default_value = "hackathon/demo")]
    project: String,
}

#[derive(Serialize, Deserialize)]
struct Report {
    project: String,
    commit: String,
    ai_generated: bool,
    security: Security,
    license: License,
    hashes: Hashes,
    timestamps: Timestamps,
    issuer: Option<String>,
    signature: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Security { score: u8, issues_count: u32 }
#[derive(Serialize, Deserialize)]
struct License  { risk: String, findings: Vec<String> }
#[derive(Serialize, Deserialize)]
struct Hashes   { tree_sha256: String, report_sha256: String }
#[derive(Serialize, Deserialize)]
struct Timestamps { analyzed_at: i64 }

abigen!(
    CodeAuditRegistry,
    r#"[ function recordAudit(bytes32,string,uint8,uint8,bool,uint64) ]"#,
);

fn get_git_commit() -> Option<String> {
    let out = Command::new("git").args(["rev-parse", "HEAD"]).output().ok()?;
    if !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn compute_tree_hash(root: &str) -> Result<String> {
    let mut concat = String::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let p = entry.path();
            if p.components().any(|c| c.as_os_str() == ".git") { continue; }
            let data = fs::read(p)?;
            let mut h = Sha256::new(); h.update(&data);
            let hex = format!("{:x}", h.finalize());
            concat.push_str(&format!("{hex}  {}\n", p.display()));
        }
    }
    let mut tree = Sha256::new(); tree.update(concat.as_bytes());
    Ok(format!("{:x}", tree.finalize()))
}

fn upload_with_storacha_cli(path: &str) -> Result<String> {
    // 사전 1회: npm i -g @storacha/cli && storacha login && storacha space create/use
    let out = Command::new("storacha").args(["put", path]).output()?;
    if !out.status.success() {
        bail!("storacha put failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 보통 마지막 토큰이 CID. 필요하면 정규식으로 더 안전하게 파싱
    let cid = stdout.split_whitespace().last()
        .ok_or_else(|| anyhow!("Failed to parse CID from storacha output"))?
        .to_string();
    Ok(cid)
}

async fn upload_with_bridge(endpoint: &str, auth: &str, secret: &str, json_bytes: Vec<u8>) -> Result<String> {
    let client = reqwest::Client::new();
    let mut req = client.post(endpoint)
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(json_bytes);
    if !secret.is_empty() {
        req = req.header("X-Auth-Secret", secret);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        bail!("Bridge upload failed: {}", resp.text().await.unwrap_or_default());
    }
    let v: serde_json::Value = resp.json().await?;
    // { "cid": "bafy..." } 형태 가정
    let cid = v.get("cid").and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("No cid in bridge response"))?
        .to_string();
    Ok(cid)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();

    // 1) 해시/점수
    let tree_hex = compute_tree_hash(&args.root)?;
    let issues_count = 0u32;
    let score = 90u8;

    // 2) 커밋 자동감지
    let commit_str = get_git_commit().unwrap_or_else(|| "NO_GIT".into());

    // 3) report.json 생성
    let mut report = Report {
        project: args.project.clone(),
        commit: commit_str.clone(),
        ai_generated: args.ai_generated,
        security: Security { score, issues_count },
        license: License { risk: "medium".into(), findings: vec![] },
        hashes: Hashes { tree_sha256: format!("0x{tree_hex}"), report_sha256: String::new() },
        timestamps: Timestamps { analyzed_at: Utc::now().timestamp() },
        issuer: None,     // did:key 넣을 거면 여기에
        signature: None,  // 서명(base64 등) 넣을 거면 여기에
    };
    let mut json = serde_json::to_vec_pretty(&report)?;
    let mut rh = Sha256::new(); rh.update(&json);
    let report_sha = format!("{:x}", rh.finalize());
    report.hashes.report_sha256 = format!("0x{report_sha}");
    json = serde_json::to_vec_pretty(&report)?;
    fs::write("report.json", &json)?;

    // 4) Storacha 업로드
    let cid = if args.use_storacha_cli {
        upload_with_storacha_cli("report.json")?
    } else {
        ensure!(!args.bridge_endpoint.is_empty() && !args.bridge_auth.is_empty(),
            "USE_STORACHA_CLI=false 인 경우 BRIDGE_ENDPOINT/BRIDGE_AUTH 필요");
        upload_with_bridge(&args.bridge_endpoint, &args.bridge_auth, &args.bridge_secret, json.clone()).await?
    };
    println!("IPFS CID: {cid}");

    // 5) 온체인 기록(Base Sepolia)근
    let provider = Provider::<Http>::try_from(args.rpc_url.clone())?;
    let wallet: LocalWallet = args.private_key.parse::<LocalWallet>()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let wallet = wallet.with_chain_id(chain_id);
    let client = SignerMiddleware::new(provider, wallet);
    let addr: Address = args.contract_addr.parse()?;
    let contract = CodeAuditRegistry::new(addr, std::sync::Arc::new(client));

    // 커밋 없는 경우 report 해시로 대체
    let commit_bytes32: [u8; 32] = if commit_str != "NO_GIT" {
        keccak256(commit_str.as_bytes())
    } else {
        keccak256(report_sha.as_bytes())
    };

    // LicenseRisk: 2(Medium)
    let binding = contract
        .record_audit(
            commit_bytes32,
            format!("ipfs://{cid}"),
            score,
            2u8,
            args.ai_generated,
            report.timestamps.analyzed_at as u64,
        );
    let tx = binding.send().await?;
    println!("tx sent: {:?}", tx.tx_hash());

    Ok(())
}
