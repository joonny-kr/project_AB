import React, { useEffect, useRef, useState } from "react";

/**
 * Fresh minimal UI
 * - Input: GitHub repo URL
 * - Calls: POST {API}/analyze -> { job_id }
 * - Polls: GET  {API}/jobs/:id   (expects snake_case statuses)
 * - Shows: BaseScan button (tx), IPFS button (CID)
 *
 * Env (optional):
 *   VITE_API       = http://localhost:8080   // leave empty to use same-origin
 *   VITE_EXPLORER  = https://basescan.org     // override if using Sepolia
 */

export default function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [cid, setCid] = useState<string | null>(null);
  const [startedAt, setStartedAt] = useState<number | null>(null);

  const API = (import.meta as any).env?.VITE_API ?? ""; // e.g. "http://localhost:8080"
  const EXPLORER = (import.meta as any).env?.VITE_EXPLORER ?? "https://sepolia.basescan.org/";

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => () => stopPolling(), []);

  function stopPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }

  function labelFrom(url: string) {
    try {
      const u = new URL(url);
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
      return u.hostname + u.pathname;
    } catch {
      return url;
    }
  }

  async function safeJson<T = any>(res: Response): Promise<T> {
    const text = await res.text();
    try { return JSON.parse(text) as T; } catch { throw new Error(text || `HTTP ${res.status}`); }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setTxHash(null); setCid(null); setJobId(null);

    const url = repoUrl.trim().replace(/#$/, "");
    if (!url) { setError("리포지토리 주소를 입력하세요."); return; }

    setPhase("running");
    setStartedAt(Date.now());

    try {
      const res = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project: labelFrom(url),
          repo_url: url,
          repo_path: null,
          commit: null,
          ai_hint: null,
          store_source_on_ipfs: null,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const { job_id } = await safeJson<{ job_id: string }>(res);
      setJobId(job_id);
      stopPolling();
      pollRef.current = setInterval(() => poll(job_id), 1200);
    } catch (e: any) {
      setPhase("error");
      setError(e?.message || String(e));
      stopPolling();
    }
  }

  async function poll(id: string) {
    try {
      const r = await fetch(`${API}/jobs/${id}`);
      if (!r.ok) throw new Error(`상태 조회 실패: ${r.status}`);
      const job = await safeJson<any>(r);
      const s = String(job.status || "").toLowerCase();

      if (s === "queued" || s === "running") { setPhase("running"); return; }
      if (s === "done") {
        setPhase("done");
        setTxHash(job.result?.tx_hash ?? null);
        setCid(job.result?.report_cid ?? null);
        stopPolling();
        return;
      }
      if (s === "error") {
        setPhase("error");
        setError(job.error || "알 수 없는 오류");
        stopPolling();
        return;
      }
      setPhase("error");
      setError(`알 수 없는 상태: ${String(job.status)}`);
      stopPolling();
    } catch (e: any) {
      setPhase("error");
      setError(e?.message || String(e));
      stopPolling();
    }
  }

  const disabled = phase === "running";

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="mx-auto max-w-3xl px-6 py-10">
        <header className="mb-8">
          <h1 className="text-4xl font-semibold tracking-tight text-gray-900">On‑Chain Code Report</h1>
          <p className="mt-2 text-sm text-gray-600">GitHub 리포지토리 URL을 입력하면 자동으로 분석 → IPFS 업로드 → Base 온체인 기록까지 진행합니다.</p>
        </header>

        <form onSubmit={handleSubmit} className="flex items-center gap-3">
          <label htmlFor="repo" className="shrink-0 text-sm text-gray-700">GitHub Repository URL</label>
          <input
            id="repo"
            type="url"
            placeholder="https://github.com/owner/repo"
            className="flex-1 rounded-xl border border-gray-300 bg-white px-4 py-2.5 text-gray-900 outline-none focus:ring-2 focus:ring-[#4f46e5]"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            disabled={disabled}
            required
          />
          <button
            type="submit"
            disabled={disabled}
            className="rounded-xl bg-[#4f46e5] px-4 py-2.5 text-white shadow hover:bg-[#4338ca] disabled:opacity-50"
          >
            {phase === "running" ? "분석 중…" : "제출"}
          </button>
        </form>

        {phase === "running" && (
          <div className="mt-6 flex items-center gap-3 rounded-xl border border-indigo-200 bg-indigo-50 px-4 py-3 text-indigo-800">
            <Spinner />
            <div>
              <p className="font-medium">로딩 중…</p>
              <p className="text-sm opacity-80">IPFS 업로드 및 온체인 기록까지 수 초~수십 초 걸릴 수 있습니다.</p>
            </div>
          </div>
        )}

        {phase === "done" && (
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            {txHash && (
              <div className="rounded-xl border p-4">
                <div className="text-sm text-gray-500">Transaction</div>
                <div className="mt-1 font-mono break-all text-gray-900">{txHash}</div>
                <a
                  className="mt-3 inline-flex rounded-lg bg-gray-900 px-3 py-2 text-sm text-white hover:bg-black"
                  href={`${EXPLORER}/tx/${txHash}`}
                  target="_blank" rel="noreferrer"
                >
                  BaseScan에서 보기
                </a>
              </div>
            )}

            {cid && (
              <div className="rounded-xl border p-4">
                <div className="text-sm text-gray-500">Report CID</div>
                <div className="mt-1 font-mono break-all text-gray-900">{cid}</div>
                <a
                  className="mt-3 inline-flex rounded-lg bg-gray-900 px-3 py-2 text-sm text-white hover:bg-black"
                  href={`https://ipfs.io/ipfs/${cid}`}
                  target="_blank" rel="noreferrer"
                >
                  IPFS에서 보기
                </a>
              </div>
            )}
          </div>
        )}

        {phase === "error" && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800">
            <p className="font-semibold">실패</p>
            <p className="mt-1 whitespace-pre-wrap text-sm opacity-90">{error}</p>
            {jobId && <p className="mt-2 text-xs opacity-70">job_id: <span className="font-mono">{jobId}</span></p>}
          </div>
        )}

        <div className="mt-8 flex justify-between text-xs text-gray-400">
          <span>{jobId ? `Job: ${jobId}` : ""}</span>
          <span>{startedAt ? `Started: ${new Date(startedAt).toLocaleString()}` : ""}</span>
        </div>
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <svg className="size-5 animate-spin" viewBox="0 0 24 24" aria-hidden>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" opacity=".25" />
      <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="4" fill="none" />
    </svg>
  );
}
