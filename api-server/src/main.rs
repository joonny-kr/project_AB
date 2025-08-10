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

//
// ---------------------------
// Types
// ---------------------------
// 타입 정의
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalyzeInput {
    /// Label (for display): org/repo or any arbitrary string
    /// 라벨(표시용): org/repo 또는 임의 문자열
    project: String,

    /// Local repository path (defaults to current directory ".")
    /// 로컬 리포지토리 경로 (미지정 시 현재 디렉터리 ".")
    repo_path: Option<String>,

    /// (Future) Remote repository URL
    /// (향후용) 원격 리포지토리 URL
    repo_url: Option<String>,

    /// (Future) Specific commit
    /// (향후용) 특정 커밋
    commit: Option<String>,

    /// (Future) AI hint
    /// (향후용) AI 힌트
    ai_hint: Option<bool>,

    /// (Future) Whether to upload full source to IPFS
    /// (향후용) 소스 전문(IPFS 업로드 여부)
    store_source_on_ipfs: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JobStatus {
    /// The job has been queued
    /// 작업이 대기열에 추가됨
    Queued,
    /// The job is currently running
    /// 작업이 실행 중
    Running,
    /// The job finished successfully
    /// 작업이 성공적으로 완료됨
    Done,
    /// The job failed
    /// 작업이 실패함
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalyzeResult {
    /// Git commit hash (string)
    /// Git 커밋 해시(문자열)
    commit: String,
    /// SHA-256 of the computed project tree snapshot
    /// 프로젝트 트리 스냅샷의 SHA-256 해시
    tree_sha256: String,
    /// Estimated percentage of AI-generated code
    /// AI 생성 코드 비율(추정)
    ai_percentage: f32,
    /// Security score (0–100)
    /// 보안 점수(0–100)
    security_score: u8,
    /// IPFS CID of the analysis report
    /// 분석 리포트의 IPFS CID
    report_cid: String,
    /// Transaction hash of the on-chain record
    /// 온체인 기록의 트랜잭션 해시
    tx_hash: String,
    /// UNIX timestamp when analysis was performed
    /// 분석 수행 시각(UNIX 타임스탬프)
    analyzed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    /// Job identifier
    /// 작업 식별자
    id: Uuid,
    /// Current status
    /// 현재 상태
    status: JobStatus,
    /// Original input
    /// 원본 입력
    input: AnalyzeInput,
    /// Successful result (if any)
    /// 성공 결과(있는 경우)
    result: Option<AnalyzeResult>,
    /// Error message (if failed)
    /// 오류 메시지(실패 시)
    error: Option<String>,
    /// Creation time (UNIX)
    /// 생성 시각(UNIX)
    created_at: i64,
}

#[derive(Clone)]
struct Config {
    /// RPC endpoint URL
    /// RPC 엔드포인트 URL
    rpc_url: String,
    /// Deployed contract address
    /// 배포된 컨트랙트 주소
    contract_addr: String,
    /// Private key used to sign transactions
    /// 트랜잭션 서명에 사용할 개인 키
    private_key: String,
    /// Demo-friendly option (allow recording the same commit multiple times)
    /// 데모 편의 옵션(동일 커밋의 중복 기록 허용)
    allow_duplicate: bool,
}

#[derive(Clone)]
struct AppState {
    /// In-memory job store
    /// 메모리 내 작업 저장소
    jobs: Arc<Mutex<HashMap<Uuid, Job>>>,
    /// Application configuration
    /// 애플리케이션 설정
    cfg: Arc<Config>,
}

//
// ---------------------------
// Solidity binding
// ---------------------------
// 솔리디티 바인딩
//

abigen!(
    /// Minimal ABI for the audit registry
    /// 감사 레지스트리를 위한 최소 ABI
    CodeAuditRegistry,
    r#"[ function recordAudit(bytes32,string,uint8,uint8,bool,uint64) ]"#,
);

//
// ---------------------------
// Main
// ---------------------------
// 메인 진입점
//

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
    println!("API가 {addr} 에서 수신 중");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

//
// ---------------------------
// HTTP Handlers
// ---------------------------
// HTTP 핸들러
//

async fn analyze(State(state): State<AppState>, Json(input): Json<AnalyzeInput>) -> Json<serde_json::Value> {
    /// Create a new job and enqueue it; return the job_id immediately.
    /// 새 작업을 생성하여 대기열에 넣고, 즉시 job_id 를 반환합니다.
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

    /// Spawn the worker task to process the job asynchronously.
    /// 작업 처리를 비동기로 수행할 워커 태스크를 생성합니다.
    let st = state.clone();
    tokio::spawn(async move {
        run_job(st, id).await;
    });

    Json(serde_json::json!({ "job_id": id }))
}

async fn get_job(State(state): State<AppState>, Path(id): Path<Uuid>) -> Json<Job> {
    /// Retrieve a single job by id.
    /// ID로 단일 작업을 조회합니다.
    let jobs = state.jobs.lock().unwrap();
    let job = jobs.get(&id).cloned().expect("invalid job id");
    Json(job)
}

async fn list_jobs(State(state): State<AppState>) -> Json<Vec<Job>> {
    /// List all jobs (unsorted). Sort before collect() if needed.
    /// 모든 작업을 나열합니다(정렬 없음). 필요 시 collect() 전에 정렬하세요.
    let jobs = state.jobs.lock().unwrap();
    Json(jobs.values().cloned().collect())
}

//
// ---------------------------
// Job runner
// ---------------------------
// 작업 실행기
//

async fn run_job(state: AppState, id: Uuid) {
    /// Mark job as Running, execute pipeline, then set Done/Error.
    /// 작업을 Running으로 표시하고 파이프라인을 실행한 뒤 Done/Error로 설정합니다.
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
    /// Update job status/result/error atomically under the lock.
    /// 락 구간에서 상태/결과/오류를 원자적으로 갱신합니다.
    let mut jobs = state.jobs.lock().unwrap();
    if let Some(j) = jobs.get_mut(&id) {
        j.status = status;
        j.result = result;
        j.error = error;
    }
}

//
// ---------------------------
// Core pipeline
// ---------------------------
// 핵심 파이프라인
//

async fn do_analyze(state: &AppState, id: Uuid) -> Result<AnalyzeResult> {
    /// Load job input from the shared store.
    /// 공유 저장소에서 작업 입력을 불러옵니다.
    let input = {
        let jobs = state.jobs.lock().unwrap();
        jobs.get(&id).expect("job not found").input.clone()
    };

    let repo_dir = PathBuf::from(input.repo_path.clone().unwrap_or_else(|| ".".into()));

    /// Decide the source of truth:
    /// - If repo_url is provided (and no local path), query GitHub API for commit & tree.
    /// - Otherwise, scan local directory and compute the tree hash.
    ///
    /// 기준 소스 선택:
    /// - repo_url 이 있고 로컬 경로가 없으면, GitHub API로 커밋/트리를 조회
    /// - 그렇지 않으면 로컬 디렉터리를 스캔하여 트리 해시 계산
    let (commit, tree_hex, analyzed_at) = if input.repo_url.is_some() && input.repo_path.is_none() {
        // ▶︎ Use GitHub API without cloning
        // ▶︎ 로컬 클론 없이 GitHub API 사용
        let repo_url = input.repo_url.clone().unwrap();
        let ref_opt = input.commit.as_deref(); // commit/branch/tag
        let (commit_sha, tree_id) = fetch_github_commit_and_tree(&repo_url, ref_opt).await?;

        // Keep the output field name "tree_sha256": store SHA-256 of the Git tree SHA string
        // 출력 필드명을 "tree_sha256"으로 유지: Git 트리 SHA 문자열의 SHA-256을 저장
        let tree_hex = sha256_hex(tree_id.as_bytes());
        let analyzed_at = Utc::now().timestamp();
        (commit_sha, tree_hex, analyzed_at)
    } else {
        // ▶︎ Local directory scan (current behavior)
        // ▶︎ 로컬 디렉터리 스캔(기본 동작)
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

    // Write report.json
    // report.json 작성
    let ai_percentage = 26.7_f32; // TODO: plug in the real AI ratio calculator
    let security_score = 90_u8;   // TODO: plug in real SAST/license analysis

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

    // Storacha CLI upload
    // Storacha CLI 업로드
    let cid = upload_with_storacha_cli(&repo_dir, &report_path)?;

    // Record on-chain
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

//
// ---------------------------
// Helpers
// ---------------------------
// 헬퍼 함수
//

fn git_commit_or_dummy(repo: &FsPath) -> String {
    /// Return current commit hash, or "NO_GIT" if not a Git repo.
    /// 현재 커밋 해시를 반환하며, Git 리포가 아니면 "NO_GIT"을 반환합니다.
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
    /// Compute a content-addressed tree hash:
    /// - For each file (excluding `.git`), hash content with SHA-256 → hex
    /// - Concatenate per-file hex hashes with newline
    /// - Hash the concatenated string again with SHA-256 → final tree hash
    ///
    /// 콘텐츠 기반 트리 해시 계산:
    /// - 각 파일(“.git” 제외)의 내용을 SHA-256으로 해싱 → 16진수
    /// - 파일별 16진수 해시를 개행으로 이어 붙임
    /// - 이어 붙인 문자열을 다시 SHA-256 해싱 → 최종 트리 해시
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

fn upload_with_storacha_cli(repo_dir: &FsPath, file_path: &FsPath) -> Result<String> {
    /// Call Storacha CLI: `storacha put <file>` and parse CID from STDOUT.
    /// Storacha CLI 호출: `storacha put <file>` 실행 후 STDOUT에서 CID를 추출합니다.
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

    /// Try to capture `bafy...` CID by regex; fallback to last token.
    /// 정규식으로 `bafy...` CID를 추출하고, 실패 시 마지막 토큰을 사용합니다.
    let re = Regex::new(r"(bafy[0-9a-z]+)")?;
    if let Some(m) = re.captures(&stdout).and_then(|c| c.get(1)) {
        return Ok(m.as_str().to_string());
    }
    if let Some(tok) = stdout.split_whitespace().last() {
        return Ok(tok.to_string());
    }
    bail!("failed to parse CID from storacha output: {stdout}");
}

async fn record_on_chain(cfg: &Config, commit: &str, score: u8, ts: i64, cid: &str) -> Result<String> {
    /// Build a signing client, prepare primary key, and send `recordAudit`.
    /// 서명 클라이언트를 구성하고 기본 키를 준비한 뒤 `recordAudit`를 전송합니다.
    let provider = Provider::<Http>::try_from(cfg.rpc_url.clone())?;
    let wallet: LocalWallet = cfg.private_key.parse::<LocalWallet>()?;
    let chain_id = provider.get_chainid().await?.as_u64();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
    let addr: Address = cfg.contract_addr.parse()?;
    let contract = CodeAuditRegistry::new(addr, std::sync::Arc::new(client));

    /// Primary key: commit hash if available; otherwise keccak256(CID)
    /// 기본 키: 커밋 해시가 있으면 그것을, 없으면 keccak256(CID) 사용
    let base: [u8; 32] = if commit == "NO_GIT" {
        keccak256(cid.as_bytes())
    } else {
        keccak256(commit.as_bytes())
    };

    /// If duplicates allowed, mix timestamp to avoid identical keys.
    /// 중복 허용 시, 동일 키 방지를 위해 타임스탬프를 섞습니다.
    let key32: [u8; 32] = if cfg.allow_duplicate {
        let mut buf = Vec::with_capacity(32 + 8);
        buf.extend_from_slice(&base);
        buf.extend_from_slice(&(ts as u64).to_be_bytes());
        keccak256(&buf)
    } else {
        base
    };

    /// LicenseRisk = 2 (Medium), aiGenerated = true
    /// 라이선스 위험도 = 2(중간), aiGenerated = true
    let call = contract.record_audit(key32, format!("ipfs://{cid}"), score, 2u8, true, ts as u64);
    let pending = call.send().await.map_err(|e| anyhow!("send tx failed: {e:#}"))?;
    Ok(format!("{:?}", pending.tx_hash()))
}

fn parse_github_owner_repo(url: &str) -> Result<(String, String)> {
    /// Parse "https://github.com/owner/repo(.git)?" to ("owner","repo")
    /// "https://github.com/owner/repo(.git)?" 형식을 ("owner","repo")로 파싱합니다.
    let re = Regex::new(r#"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"#)?;
    let caps = re.captures(url).ok_or_else(|| anyhow!("unsupported repo_url: {url}"))?;
    Ok((caps[1].to_string(), caps[2].to_string()))
}

async fn fetch_github_commit_and_tree(
    repo_url: &str,
    ref_opt: Option<&str>,
) -> Result<(String /*commit_sha*/, String /*tree_sha*/)> {
    /// Query GitHub: resolve ref → commit, then extract commit.sha and commit.tree.sha.
    /// GitHub 조회: ref → commit을 해석하고, commit.sha 및 commit.tree.sha를 추출합니다.
    let (owner, repo) = parse_github_owner_repo(repo_url)?;
    let reference = ref_opt.unwrap_or("heads/main"); // If not provided, try main (or default branch HEAD)
    // 제공되지 않으면 main(또는 기본 브랜치 HEAD)로 시도합니다.

    let token = std::env::var("GITHUB_TOKEN").ok(); // required for private repos
    // 프라이빗 리포지토리 접근 시 필요
    let client = reqwest::Client::new();

    // 1) Resolve ref → commit (we get tree.sha here)
    // /commits/{ref} accepts branch name, tag, or commit SHA
    // 1) ref 해석 → commit (여기서 tree.sha 획득)
    // /commits/{ref} 는 브랜치명, 태그, 커밋 SHA 모두 허용
    let url = format!("https://api.github.com/repos/{owner}/{repo}/commits/{reference}");
    let mut req = client.get(&url).header(USER_AGENT, "code-audit-bot/1.0");
    if let Some(t) = token.as_deref() {
        req = req.header(AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = req.send().await?.error_for_status()?;
    let v: serde_json::Value = resp.json().await?;

    // Example structure:
    // {
    //   "sha": "commit_sha",
    //   "commit": { "tree": { "sha": "tree_sha", ... }, ... },
    //   ...
    // }
    // 응답 예시 구조(상동)

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

fn sha256_hex<B: AsRef<[u8]>>(b: B) -> String {
    /// Compute SHA-256 of input bytes and return lowercase hex string.
    /// 입력 바이트의 SHA-256을 계산하여 소문자 16진수 문자열로 반환합니다.
    let mut h = Sha256::new();
    h.update(b.as_ref());
    format!("{:x}", h.finalize())
}
