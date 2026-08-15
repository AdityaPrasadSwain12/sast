import type { ScanJob, ScanReport, TargetType } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function jsonRequest<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error ?? response.statusText);
  }
  return response.json() as Promise<T>;
}

export async function createUrlScan(githubUrl: string): Promise<ScanJob> {
  return jsonRequest<ScanJob>("/api/scans/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_type: "github", github_url: githubUrl })
  });
}

export async function createLocalPathScan(localPath: string): Promise<ScanJob> {
  return jsonRequest<ScanJob>("/api/scans/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_type: "local_path", local_path: localPath })
  });
}

export async function createUploadScan(targetType: Extract<TargetType, "file" | "folder">, files: File[]): Promise<ScanJob> {
  const form = new FormData();
  form.append("target_type", targetType);
  files.forEach((file) => {
    form.append("files", file);
    form.append("relative_paths", webkitRelativePath(file));
  });
  return jsonRequest<ScanJob>("/api/scans/", { method: "POST", body: form });
}

export async function getScan(jobId: string): Promise<ScanJob> {
  return jsonRequest<ScanJob>(`/api/scans/${jobId}/`);
}

export async function listScans(): Promise<ScanJob[]> {
  const payload = await jsonRequest<{ results: ScanJob[] }>("/api/scans/");
  return payload.results;
}

export async function getReport(job: ScanJob): Promise<ScanReport> {
  return jsonRequest<ScanReport>(job.reports.json);
}

export async function getLatestReport(): Promise<ScanReport> {
  return jsonRequest<ScanReport>("/api/reports/latest/");
}

function webkitRelativePath(file: File): string {
  const candidate = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
  return candidate && candidate.length > 0 ? candidate : file.name;
}
