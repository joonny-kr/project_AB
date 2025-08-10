use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use anyhow::*;
use chrono::Utc;
use dotenvy::dotenv;
use ethers::prelude::*;
use ethers::utils::keccak256;
use regex::Regex;
use reqwest::header::{AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tokio::task;
use uuid::Uuid;
use walkdir::WalkDir;

// ---------------------------
// Types
// ---------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalyzeInput {
    /// 라벨(표시용): org/repo 혹은 임의 문자열
    project: String,

    /// 로컬 리포 경로 (미지정 시 현재 디렉토리 ".")
    repo_path: Option<String>,

    /// (향후용) 원격 리포 URL
    repo_url: Option<String>,

    /// (향후용) 특정 커밋
    commit: Option<String>,

    /// (향후용) AI 힌트
    ai_hint: Option<bool>,

    /// (향후용) 소스 전문 업로드 여부
    store_source_on_ipfs: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JobStatus {
    Queued,
    Running,
    Done,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalyzeResult {
    commit: String,
    tree_sha256: String,
    ai_percentage: f32,
    security_score: u8,
    report_cid: String,
    tx_hash: String,
    analyzed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    id: Uuid,
    status: JobStatus,
    input: AnalyzeInput,
    result: Option<AnalyzeResult>,
    error: Option<String>,
    created_at: i64,
}

#[derive(Clone)]
struct Config {
    rpc_url: String,
    contract_addr: String,
    private_key: String,
    allow_duplicate: bool, // 데모 반복용(동일 커밋에도 여러 번 기록)
}

#[derive(Clone)]
struct AppState {
    jobs: Arc<Mutex<HashMap<Uuid, Job>>>,
    cfg: Arc<Config>,
}

// ---------------------------
// Solidity binding
// ---------------------------

abigen!(
    CodeAuditRegistry,
    r#"[ function recordAudit(bytes32,string,uint8,uint8,bool,uint64) ]"#,
);

// ---------------------------
// Main
// ---------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let cfg = Config {
        rpc_url: std::env::var("RPC_URL")?,
        contract_addr: std::env::var("CONTRACT_ADDR")?,
        private_key: std::env::var("PRIVATE_KEY")?,
        allow_duplicate: std::env::var("ALLOW_DUPLICATE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
    };

    let state = AppState {
        jobs: Arc::new(Mutex::new(HashMap::new())),
        cfg: Arc::new(cfg),
    };

    let app = Router::new()
        .route("/analyze", post(analyze))
        .route("/jobs/:id", get(get_job))
        .route("/jobs", get(list_jobs))
        .with_state(state);

    let addr = std::env::var("PORT")
        .map(|p| format!("0.0.0.0:{}", p))
        .unwrap_or_else(|_| "0.0.0.0:8080".into());

    println!("API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------
// HTTP Handlers
// ---------------------------

async fn analyze(State(state): State<AppState>, Json(input): Json<AnalyzeInput>) -> Json<serde_json::Value> {
    let id = Uuid::new_v4();

    {
        let mut jobs = state.jobs.lock().unwrap();
        jobs.insert(
            id,
            Job {
                id,
                status: JobStatus::Queued,
                input: input.clone(),
                result: None,
                error: None,
                created_at: Utc::now().timestamp(),
            },
        );
    }

    let st = state.clone();
    tokio::spawn(async move {
        run_job(st, id).await;
    });

    Json(serde_json::json!({ "job_id": id }))
}

async fn get_job(State(state): State<AppState>, Path(id): Path<Uuid>) -> Json<Job> {
    let jobs = state.jobs.lock().unwrap();
    let job = jobs.get(&id).cloned().expect("invalid job id");
    Json(job)
}

async fn list_jobs(State(state): State<AppState>) -> Json<Vec<Job>> {
    let jobs = state.jobs.lock().unwrap();
    // 최신순으로 보고 싶으면 collect 전에 정렬해도 OK
    Json(jobs.values().cloned().collect())
}

// ---------------------------
// Job runner
// ---------------------------

async fn run_job(state: AppState, id: Uuid) {
    set_status(&state, id, JobStatus::Running, None, None);

    let (res, err) = do_analyze(&state, id)
        .await
        .map(|r| (Some(r), None))
        .unwrap_or_else(|e| (None, Some(format!("{e:#}"))));

    if let Some(r) = res {
        set_status(&state, id, JobStatus::Done, Some(r), None);
    } else if let Some(e) = err {
        set_status(&state, id, JobStatus::Error, None, Some(e));
    }
}

fn set_status(state: &AppState, id: Uuid, status: JobStatus, result: Option<AnalyzeResult>, error: Option<String>) {
    let mut jobs = state.jobs.lock().unwrap();
    if let Some(j) = jobs.get_mut(&id) {
        j.status = status;
        j.result = result;
        j.error = error;
    }
}

// ---------------------------
// Core pipeline
// ---------------------------

async fn do_analyze(state: &AppState, id: Uuid) -> Result<AnalyzeResult> {
    // 입력 꺼내기
    let input = {
        let jobs = state.jobs.lock().unwrap();
        jobs.get(&id).expect("job not found").input.clone()
    };

    let repo_dir = PathBuf::from(input.repo_path.clone().unwrap_or_else(|| ".".into()));

    let (commit, tree_hex, analyzed_at) = if input.repo_url.is_some() && input.repo_path.is_none() {
        // ▶︎ 클론 없이 GitHub API 사용
        let repo_url = input.repo_url.clone().unwrap();
        let ref_opt = input.commit.as_deref(); // 커밋/브랜치/태그 아무거나
        let (commit_sha, tree_id) = fetch_github_commit_and_tree(&repo_url, ref_opt).await?;

        // 필드 이름은 그대로 "tree_sha256"을 쓰고 싶으니, Git 트리 SHA 문자열에 대해 SHA-256을 한 값을 저장
        let tree_hex = sha256_hex(tree_id.as_bytes());
        let analyzed_at = Utc::now().timestamp();
        (commit_sha, tree_hex, analyzed_at)
    } else {
        // ▶︎ 로컬 디렉토리 스캔 (기존 동작)
        let repo_dir2 = repo_dir.clone();
        task::spawn_blocking(move || -> Result<(String, String, i64)> {
            if !repo_dir2.exists() {
                bail!("repo_path not found: {}", repo_dir2.display());
            }
            let commit = git_commit_or_dummy(&repo_dir2);
            let tree_hex = compute_tree_hash(&repo_dir2)?;
            let analyzed_at = Utc::now().timestamp();
            Ok((commit, tree_hex, analyzed_at))
        })
        .await
        .unwrap()?
    };

    // report.json 작성
    let ai_percentage = 26.7_f32; // TODO: 실제 AI 비율 계산기 붙이기
    let security_score = 90_u8; // TODO: 실제 SAST/라이선스 분석 붙이기

    let report = serde_json::json!({
        "project": input.project,
        "commit": commit,
        "ai_generated": true,
        "ai": { "percentage": ai_percentage },
        "security": { "score": security_score, "issues_count": 0 },
        "hashes": { "tree_sha256": format!("0x{tree_hex}") },
        "timestamps": { "analyzed_at": analyzed_at }
    });
    let report_path = repo_dir.join("report.json");
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    // Storacha CLI 업로드
    let cid = upload_with_storacha_cli(&repo_dir, &report_path)?;

    // 온체인 기록
    let tx_hash = record_on_chain(
        &state.cfg,
        &commit,
        security_score,
        analyzed_at,
        &cid,
    )
    .await?;

    Ok(AnalyzeResult {
        commit,
        tree_sha256: tree_hex,
        ai_percentage,
        security_score,
        report_cid: cid,
        tx_hash,
        analyzed_at,
    })
}

// ---------------------------
// Helpers
// ---------------------------

fn git_commit_or_dummy(repo: &FsPath) -> String {
    match Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
    {
        std::result::Result::Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "NO_GIT".into(),
    }
}

fn compute_tree_hash(root: &FsPath) -> Result<String> {
    let mut concat = String::new();
    for e in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if e.file_type().is_file() {
            let p = e.path();
            if p.components().any(|c| c.as_os_str() == ".git") {
                continue;
            }
            let data = fs::read(p)?;
            let mut h = Sha256::new();
            h.update(&data);
            let file_hex = format!("{:x}", h.finalize());
            concat.push_str(&file_hex);
            concat.push('\n');
        }
    }
    let mut tree = Sha256::new();
    tree.update(concat.as_bytes());
    Ok(format!("{:x}", tree.finalize()))
}

// Storacha CLI 호출: `storacha put <file>` → STDOUT에서 CID 추출
fn upload_with_storacha_cli(repo_dir: &FsPath, file_path: &FsPath) -> Result<String> {
    let out = Command::new("storacha")
        .args(["put", file_path.to_str().ok_or_else(|| anyhow!("bad path"))?])
        .current_dir(repo_dir)
        .output()?;

    if !out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("storacha put failed\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let re = Regex::new(r"(bafy[0-9a-z]+)")?;
    if let Some(m) = re.captures(&stdout).and_then(|c| c.get(1)) {
        return Ok(m.as_str().to_string());
    }
    // fallback: 마지막 토큰
    if let Some(tok) = stdout.split_whitespace().last() {
        return Ok(tok.to_string());
    }
    bail!("failed to parse CID from storacha output: {stdout}");
}

async fn record_on_chain(cfg: &Config, commit: &str, score: u8, ts: i64, cid: &str) -> Result<String> {
    let provider = Provider::<Http>::try_from(cfg.rpc_url.clone())?;
    let wallet: LocalWallet = cfg.private_key.parse::<LocalWallet>()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let addr: Address = cfg.contract_addr.parse()?;
    let contract = CodeAuditRegistry::new(addr, std::sync::Arc::new(client));

    // 기본키: 커밋이 있으면 그 해시, 없으면 CID 해시
    let base: [u8; 32] = if commit == "NO_GIT" {
        keccak256(cid.as_bytes())
    } else {
        keccak256(commit.as_bytes())
    };

    // 데모 반복용 옵션: 실행 시각을 섞어 중복 회피
    let key32: [u8; 32] = if cfg.allow_duplicate {
        let mut buf = Vec::with_capacity(32 + 8);
        buf.extend_from_slice(&base);
        buf.extend_from_slice(&(ts as u64).to_be_bytes());
        keccak256(&buf)
    } else {
        base
    };

    // LicenseRisk=2(Medium), aiGenerated=true
    let call = contract.record_audit(key32, format!("ipfs://{cid}"), score, 2u8, true, ts as u64);
    let pending = call.send().await.map_err(|e| anyhow!("send tx failed: {e:#}"))?;
    Ok(format!("{:?}", pending.tx_hash()))
}

// "https://github.com/owner/repo(.git)?" -> ("owner","repo")
fn parse_github_owner_repo(url: &str) -> Result<(String, String)> {
    let re = Regex::new(r#"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"#)?;
    let caps = re.captures(url).ok_or_else(|| anyhow!("unsupported repo_url: {url}"))?;
    Ok((caps[1].to_string(), caps[2].to_string()))
}

async fn fetch_github_commit_and_tree(
    repo_url: &str,
    ref_opt: Option<&str>,
) -> Result<(String /*commit_sha*/, String /*tree_sha*/)> {
    let (owner, repo) = parse_github_owner_repo(repo_url)?;
    let reference = ref_opt.unwrap_or("heads/main"); // ref를 안 주면 main(또는 default branch HEAD)로 시도
    // 참고: 보편적으로는 "main" 또는 "master"인데, 정확한 default branch를 쓰려면 /repos API로 default_branch를 먼저 조회하세요.

    let token = std::env::var("GITHUB_TOKEN").ok(); // private repo면 필요
    let client = reqwest::Client::new();

    // 1) ref → 커밋 조회 (여기서 tree.sha를 얻음)
    // /commits/{ref} 는 브랜치명, 태그, 커밋해시 모두 허용
    let url = format!("https://api.github.com/repos/{owner}/{repo}/commits/{reference}");
    let mut req = client.get(&url).header(USER_AGENT, "code-audit-bot/1.0");
    if let Some(t) = token.as_deref() {
        req = req.header(AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = req.send().await?.error_for_status()?;
    let v: serde_json::Value = resp.json().await?;

    // 예시 구조:
    // {
    //   "sha": "commit_sha",
    //   "commit": { "tree": { "sha": "tree_sha", ... }, ... },
    //   ...
    // }
    let commit_sha = v.get("sha")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing commit.sha"))?
        .to_string();

    let tree_sha = v.get("commit")
        .and_then(|c| c.get("tree"))
        .and_then(|t| t.get("sha"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("missing commit.tree.sha"))?
        .to_string();

    Ok((commit_sha, tree_sha))
}

// 문자열 또는 바이트를 SHA-256(hex)로
fn sha256_hex<B: AsRef<[u8]>>(b: B) -> String {
    let mut h = Sha256::new();
    h.update(b.as_ref());
    format!("{:x}", h.finalize())
}