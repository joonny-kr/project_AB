import React, { useEffect, useRef, useState } from "react";

export default function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [cid, setCid] = useState<string | null>(null);
  const [startedAt, setStartedAt] = useState<number | null>(null);

  const API = (import.meta as any).env?.VITE_API ?? "";
  const EXPLORER =
    (import.meta as any).env?.VITE_EXPLORER ?? "https://sepolia.basescan.org";

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
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(text || `HTTP ${res.status}`);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setTxHash(null);
    setCid(null);
    setJobId(null);

    const url = repoUrl.trim().replace(/#$/, "");
    if (!url) {
      setError("Please enter a repository URL.");
      return;
    }

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
      if (!r.ok) throw new Error(`Status check failed: ${r.status}`);
      const job = await safeJson<any>(r);
      const s = String(job.status || "").toLowerCase();

      if (s === "queued" || s === "running") {
        setPhase("running");
        return;
      }
      if (s === "done") {
        setPhase("done");
        setTxHash(job.result?.tx_hash ?? null);
        setCid(job.result?.report_cid ?? null);
        stopPolling();
        return;
      }
      if (s === "error") {
        setPhase("error");
        setError(job.error || "Unknown error");
        stopPolling();
        return;
      }
      setPhase("error");
      setError(`Unknown status: ${String(job.status)}`);
      stopPolling();
    } catch (e: any) {
      setPhase("error");
      setError(e?.message || String(e));
      stopPolling();
    }
  }

  function copy(text: string) {
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  const disabled = phase === "running";

  return (
    <div className="grid min-h-screen w-screen place-items-center bg-gray-50 px-4">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-lg">
        <header className="mb-8 text-center">
          <h1 className="text-4xl font-semibold tracking-tight text-gray-900">
            On-Chain Code Report
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            Enter a GitHub repository URL to analyze, upload to IPFS, and record on
            the Base blockchain.
          </p>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <label
            htmlFor="repo"
            className="shrink-0 text-sm text-gray-700 text-left"
          >
            GitHub Repository URL
          </label>
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
            className={`rounded-xl px-4 py-2.5 text-white shadow ${
              phase === "running"
                ? "!bg-white !text-gray-900 !border-gray-300 cursor-wait hover:!bg-white"
                : "!bg-blue-600 !text-white hover:!bg-blue-700 border-transparent"
            } disabled:opacity-50`}
          >
            {phase === "running" ? "Analyzing..." : "Submit"}
          </button>
        </form>

        {phase === "running" && (
          <div className="mt-6 flex items-center gap-3 rounded-xl border border-indigo-200 bg-indigo-50 px-4 py-3 text-indigo-800">
            <Spinner />
            <div>
              <p className="font-medium">Loading...</p>
              <p className="text-sm opacity-80">
                Uploading to IPFS and recording on-chain may take a few to several
                seconds.
              </p>
            </div>
          </div>
        )}

        {phase === "done" && (
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            {txHash && (
              <div className="rounded-xl border p-4">
                <div className="text-sm text-gray-500">Transaction</div>
                <div className="mt-1 flex items-center gap-2">
                  <code
                    title={txHash}
                    className="font-mono text-gray-900 w-full overflow-hidden whitespace-nowrap text-ellipsis"
                  >
                    {txHash}
                  </code>
                  <button
                    type="button"
                    onClick={() => copy(txHash)}
                    className="shrink-0 rounded-md border !border-gray-700 !px-1.5 !py-0.5 !text-[12px] hover:!bg-gray-100"
                  >
                    Copy
                  </button>
                </div>
                <a
                  className="mt-3 inline-flex rounded-lg bg-gray-900 px-3 py-2 text-sm text-white hover:bg-black"
                  href={`${EXPLORER}/tx/${txHash}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  View on BaseScan
                </a>
              </div>
            )}

            {cid && (
              <div className="rounded-xl border p-4">
                <div className="text-sm text-gray-500">Report CID</div>
                <div className="mt-1 flex items-center gap-2">
                  <code
                    title={cid}
                    className="font-mono text-gray-900 w-full overflow-hidden whitespace-nowrap text-ellipsis"
                  >
                    {cid}
                  </code>
                  <button
                    type="button"
                    onClick={() => copy(cid)}
                    className="shrink-0 rounded-md border !border-gray-700 !px-1.5 !py-0.5 !text-[12px] hover:!bg-gray-100"
                  >
                    Copy
                  </button>
                </div>
                <a
                  className="mt-3 inline-flex rounded-lg bg-gray-900 px-3 py-2 text-sm text-white hover:bg-black"
                  href={`https://ipfs.io/ipfs/${cid}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  View on IPFS
                </a>
              </div>
            )}
          </div>
        )}

        {phase === "error" && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800">
            <p className="font-semibold">Error</p>
            <p className="mt-1 whitespace-pre-wrap text-sm opacity-90">
              {error}
            </p>
            {jobId && (
              <p className="mt-2 text-xs opacity-70">
                job_id: <span className="font-mono">{jobId}</span>
              </p>
            )}
          </div>
        )}

        <div className="mt-8 flex justify-between text-xs text-gray-400">
          <span>{jobId ? `Job: ${jobId}` : ""}</span>
          <span>
            {startedAt ? `Started: ${new Date(startedAt).toLocaleString()}` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <svg
      className="size-5 animate-spin"
      viewBox="0 0 24 24"
      aria-hidden
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
        fill="none"
        opacity=".25"
      />
      <path
        d="M4 12a8 8 0 018-8"
        stroke="currentColor"
        strokeWidth="4"
        fill="none"
      />
    </svg>
  );
}
