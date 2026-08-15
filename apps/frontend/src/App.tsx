import { ChangeEvent, ReactNode, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Code2,
  Database,
  Download,
  ExternalLink,
  FileArchive,
  FileCode2,
  FileJson,
  Folder,
  Gauge,
  Home,
  Link,
  Loader2,
  Play,
  RefreshCcw,
  Search,
  Settings,
  Shield,
  TerminalSquare
} from "lucide-react";
import {
  createLocalPathScan,
  createUploadScan,
  createUrlScan,
  getLatestReport,
  getReport,
  getScan,
  listScans
} from "./api";
import type { Finding, ScanJob, ScanReport, TargetType } from "./types";

type Page = "dashboard" | "new-scan" | "reports" | "rules" | "settings";

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const finalStatuses = ["SUCCESS", "FAILED", "PARTIAL", "ERROR"];

export default function App() {
  const [page, setPage] = useState<Page>("new-scan");
  const [targetType, setTargetType] = useState<TargetType>("github");
  const [githubUrl, setGithubUrl] = useState("https://github.com/OWASP/NodeGoat");
  const [localPath, setLocalPath] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const isBusy = job?.status === "QUEUED" || job?.status === "RUNNING";

  useEffect(() => {
    refreshHistory();
    getLatestReport().then(setReport).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!job || !isBusy) return;
    const timer = window.setInterval(async () => {
      try {
        const next = await getScan(job.id);
        setJob(next);
        if (finalStatuses.includes(next.status)) {
          window.clearInterval(timer);
          await loadReport(next);
          await refreshHistory();
        }
      } catch (pollError) {
        setError(pollError instanceof Error ? pollError.message : "Unable to refresh scan status");
      }
    }, 2500);
    return () => window.clearInterval(timer);
  }, [job, isBusy]);

  const findings = useMemo(() => {
    const all = report?.findings ?? [];
    if (!query.trim()) return all;
    const normalized = query.toLowerCase();
    return all
      .filter((finding) =>
        [finding.title, finding.rule_id, finding.file, finding.scanner, finding.category, finding.cve]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalized))
      );
  }, [query, report]);

  async function refreshHistory() {
    try {
      setHistory(await listScans());
    } catch {
      setHistory([]);
    }
  }

  async function loadReport(nextJob: ScanJob) {
    setJob(nextJob);
    if (!finalStatuses.includes(nextJob.status)) {
      setReport(null);
      return;
    }
    try {
      setReport(await getReport(nextJob));
    } catch {
      setReport(null);
    }
  }

  async function startScan() {
    setError("");
    setReport(null);
    const validation = validateScanInput(targetType, githubUrl, localPath, files);
    if (validation) {
      setError(validation);
      return;
    }

    try {
      const created =
        targetType === "github"
          ? await createUrlScan(githubUrl.trim())
          : targetType === "local_path"
            ? await createLocalPathScan(localPath.trim())
            : await createUploadScan(targetType, files);
      setJob(created);
      setPage("new-scan");
      await refreshHistory();
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Unable to start scan");
    }
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    setFiles(Array.from(event.target.files ?? []));
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <Shield size={28} />
          <span>SAST Scan</span>
        </div>
        <nav className="nav">
          <NavButton active={page === "dashboard"} icon={<Home size={18} />} onClick={() => setPage("dashboard")}>
            Dashboard
          </NavButton>
          <NavButton active={page === "new-scan"} icon={<Gauge size={18} />} onClick={() => setPage("new-scan")}>
            New Scan
          </NavButton>
          <NavButton active={page === "reports"} icon={<FileJson size={18} />} onClick={() => setPage("reports")}>
            Reports
          </NavButton>
          <NavButton active={page === "rules"} icon={<Code2 size={18} />} onClick={() => setPage("rules")}>
            Rules
          </NavButton>
          <NavButton active={page === "settings"} icon={<Settings size={18} />} onClick={() => setPage("settings")}>
            Settings
          </NavButton>
        </nav>
        <div className="sidebar-card">
          <span>Scanner Stack</span>
          <strong>OpenGrep + Trivy</strong>
          <small>Containerized execution</small>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <h1>{pageTitle(page)}</h1>
            <p>{pageSubtitle(page)}</p>
          </div>
          <div className={`status-pill ${statusClass(job?.status ?? "READY")}`}>{job?.status ?? "READY"}</div>
        </header>

        {page === "dashboard" && <DashboardPage job={job} report={report} history={history} onOpenReports={() => setPage("reports")} />}
        {page === "new-scan" && (
          <ScanPage
            targetType={targetType}
            setTargetType={setTargetType}
            githubUrl={githubUrl}
            setGithubUrl={setGithubUrl}
            localPath={localPath}
            setLocalPath={setLocalPath}
            files={files}
            onFileChange={onFileChange}
            startScan={startScan}
            isBusy={isBusy}
            error={error}
            job={job}
            report={report}
            findings={findings}
            query={query}
            setQuery={setQuery}
          />
        )}
        {page === "reports" && <ReportsPage history={history} onRefresh={refreshHistory} onOpen={loadReport} selectedJob={job} />}
        {page === "rules" && <RulesPage />}
        {page === "settings" && <SettingsPage />}
      </main>
    </div>
  );
}

function ScanPage(props: {
  targetType: TargetType;
  setTargetType: (value: TargetType) => void;
  githubUrl: string;
  setGithubUrl: (value: string) => void;
  localPath: string;
  setLocalPath: (value: string) => void;
  files: File[];
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void;
  startScan: () => void;
  isBusy: boolean;
  error: string;
  job: ScanJob | null;
  report: ScanReport | null;
  findings: Finding[];
  query: string;
  setQuery: (value: string) => void;
}) {
  return (
    <section className="layout-grid scan-layout">
      <div className="main-column">
        <section className="panel">
          <div className="tabs">
            <TabButton active={props.targetType === "file"} icon={<FileCode2 size={17} />} onClick={() => props.setTargetType("file")}>
              File Upload
            </TabButton>
            <TabButton active={props.targetType === "folder"} icon={<Folder size={17} />} onClick={() => props.setTargetType("folder")}>
              Folder Upload
            </TabButton>
            <TabButton active={props.targetType === "github"} icon={<Link size={17} />} onClick={() => props.setTargetType("github")}>
              GitHub URL
            </TabButton>
            <TabButton active={props.targetType === "local_path"} icon={<TerminalSquare size={17} />} onClick={() => props.setTargetType("local_path")}>
              Local Path
            </TabButton>
          </div>

          <div className="target-row">
            {props.targetType === "github" && (
              <label className="field">
                Repository URL
                <input value={props.githubUrl} onChange={(event) => props.setGithubUrl(event.target.value)} placeholder="https://github.com/org/repository" />
              </label>
            )}
            {props.targetType === "local_path" && (
              <label className="field">
                Workspace path
                <input value={props.localPath} onChange={(event) => props.setLocalPath(event.target.value)} placeholder="C:\\Users\\adity\\OneDrive\\Desktop\\SAST_SCAN\\target.java" />
              </label>
            )}
            {props.targetType === "file" && (
              <label className="dropzone">
                <FileArchive size={24} />
                <span>{props.files[0]?.name ?? "Choose a source file"}</span>
                <input type="file" onChange={props.onFileChange} />
              </label>
            )}
            {props.targetType === "folder" && (
              <label className="dropzone">
                <Folder size={24} />
                <span>{props.files.length ? `${props.files.length} files selected` : "Choose a project folder"}</span>
                <input type="file" multiple webkitdirectory="true" onChange={props.onFileChange} />
              </label>
            )}
            <button className="primary-action" disabled={props.isBusy} onClick={props.startScan}>
              {props.isBusy ? <Loader2 className="spin" size={18} /> : <Play size={18} />} Start Scan
            </button>
          </div>
          {props.error && (
            <div className="error-banner">
              <AlertTriangle size={16} />
              {props.error}
            </div>
          )}
        </section>

        <ProgressPanel job={props.job} />
        <SeverityCards summary={props.report?.summary ?? props.job?.summary ?? {}} />
      </div>

      <aside className="side-column">
        <ScannerStatus report={props.report} job={props.job} />
        <ReportPanel job={props.job} report={props.report} />
      </aside>

      <div className="findings-wide">
        <FindingsPanel findings={props.findings} query={props.query} setQuery={props.setQuery} job={props.job} report={props.report} />
      </div>
    </section>
  );
}

function DashboardPage({ job, report, history, onOpenReports }: { job: ScanJob | null; report: ScanReport | null; history: ScanJob[]; onOpenReports: () => void }) {
  const totalScans = history.length;
  const totalFindings = report?.summary.TOTAL ?? job?.summary.TOTAL ?? 0;
  return (
    <section className="layout-grid single-column">
      <div className="dashboard-grid">
        <SummaryTile label="Last Scan Status" value={job?.status ?? "READY"} tone={statusClass(job?.status ?? "READY")} />
        <SummaryTile label="Findings In Last Scan" value={totalFindings} tone="failed" />
        <SummaryTile label="Files Scanned" value={job?.coverage?.files_scanned ?? "-"} tone="success" />
        <SummaryTile label="Saved Scan Jobs" value={totalScans} tone="info" />
      </div>
      <section className="panel table-panel">
        <div className="table-head">
          <h2>Recent Activity</h2>
          <button className="secondary-button button-reset" onClick={onOpenReports}>
            View Reports
          </button>
        </div>
        <HistoryTable history={history.slice(0, 6)} onOpen={() => undefined} selectedJob={job} />
      </section>
    </section>
  );
}

function ReportsPage({ history, onRefresh, onOpen, selectedJob }: { history: ScanJob[]; onRefresh: () => void; onOpen: (job: ScanJob) => void; selectedJob: ScanJob | null }) {
  return (
    <section className="layout-grid single-column">
      <section className="panel table-panel">
        <div className="table-head">
          <h2>Scan Reports</h2>
          <button className="secondary-button button-reset" onClick={onRefresh}>
            <RefreshCcw size={16} /> Refresh
          </button>
        </div>
        <HistoryTable history={history} onOpen={onOpen} selectedJob={selectedJob} />
      </section>
    </section>
  );
}

function RulesPage() {
  return (
    <section className="layout-grid single-column">
      <section className="panel info-panel">
        <h2>Rules Configuration</h2>
        <div className="info-grid">
          <InfoBlock title="Community Rules" value="rules/opengrep/community" detail="Language packs used by OpenGrep for broad SAST coverage." />
          <InfoBlock title="Custom Gap Rules" value="rules/opengrep/custom/security.yaml" detail="Project-owned checks used where community rules need extra coverage." />
          <InfoBlock title="Scanner Config" value="configs/scanner.yaml" detail="Controls enabled engines, rule paths, timeouts, reports, and thresholds." />
          <InfoBlock title="Trivy Database" value="Managed by Trivy container" detail="Used by Trivy for dependency, secret, and misconfiguration scanning." />
        </div>
      </section>
    </section>
  );
}

function SettingsPage() {
  return (
    <section className="layout-grid single-column">
      <section className="panel info-panel">
        <h2>Runtime Settings</h2>
        <div className="info-grid">
          <InfoBlock title="API Base URL" value={import.meta.env.VITE_API_BASE_URL ?? "same-origin"} detail="Set VITE_API_BASE_URL when the Django API runs on another origin." />
          <InfoBlock title="Report Storage" value="reports/scan.*" detail="Each web scan overwrites the latest JSON, HTML, SARIF, and PDF report files." />
          <InfoBlock title="Backend Entry" value="apps/backend/manage.py" detail="Django API that starts scanner jobs and exposes report endpoints." />
          <InfoBlock title="Frontend Entry" value="apps/frontend/src/App.tsx" detail="React application shell for uploads, GitHub scans, history, and report access." />
        </div>
      </section>
    </section>
  );
}

function HistoryTable({ history, onOpen, selectedJob }: { history: ScanJob[]; onOpen: (job: ScanJob) => void; selectedJob: ScanJob | null }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Target</th>
          <th>Findings</th>
          <th>Files</th>
          <th>Created</th>
          <th>Reports</th>
        </tr>
      </thead>
      <tbody>
        {history.length === 0 && (
          <tr>
            <td colSpan={6} className="empty-cell">No scan history yet.</td>
          </tr>
        )}
        {history.map((item) => (
          <tr key={item.id} className={selectedJob?.id === item.id ? "selected-row" : ""}>
            <td><span className={`badge ${statusClass(item.status)}`}>{item.status}</span></td>
            <td>{item.target}</td>
            <td>{item.summary.TOTAL ?? 0}</td>
            <td>{item.coverage?.files_scanned ?? "-"}</td>
            <td>{new Date(item.created_at).toLocaleString()}</td>
            <td>
              <div className="inline-actions">
                <button className="icon-button" onClick={() => onOpen(item)} title="Load report">
                  <ExternalLink size={16} />
                </button>
                <a className="icon-button" href={item.reports.pdf} target="_blank" title="Download PDF report">
                  <Download size={16} />
                </a>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ProgressPanel({ job }: { job: ScanJob | null }) {
  const active = job?.status === "RUNNING" || job?.status === "QUEUED";
  const progress = job?.status === "RUNNING" ? 68 : job?.status === "QUEUED" ? 18 : job ? 100 : 0;
  return (
    <section className="panel">
      <div className="progress-head">
        <strong>{active ? "Scanning in progress..." : job ? "Scan completed" : "Ready to scan"}</strong>
        <span>{progress}%</span>
      </div>
      <div className="progress-track"><div style={{ width: `${progress}%` }} /></div>
      <div className="metric-row">
        <Metric icon={<FileCode2 size={22} />} label="Files Scanned" value={job?.coverage?.files_scanned ?? "-"} />
        <Metric icon={<Code2 size={22} />} label="Lines Scanned" value={job?.coverage?.lines_scanned ?? "-"} />
        <Metric icon={<Database size={22} />} label="Integrity" value={integrityLabel(job)} />
      </div>
    </section>
  );
}

function SeverityCards({ summary }: { summary: Record<string, number> }) {
  return (
    <section className="severity-grid">
      {severityOrder.slice(0, 5).map((severity) => (
        <div className="severity-card" key={severity}>
          <span className={`severity-name ${severity.toLowerCase()}`}>{severity}</span>
          <strong>{summary[severity] ?? 0}</strong>
          <div className={`severity-bar ${severity.toLowerCase()}`} />
        </div>
      ))}
      <div className="severity-card total">
        <span>Total Findings</span>
        <strong>{summary.TOTAL ?? 0}</strong>
        <div className="severity-bar total" />
      </div>
    </section>
  );
}

function FindingsPanel({ findings, query, setQuery, job, report }: { findings: Finding[]; query: string; setQuery: (value: string) => void; job: ScanJob | null; report: ScanReport | null }) {
  const jsonHref = job && finalStatuses.includes(job.status) ? job.reports.json : report ? "/api/reports/latest/json/" : "";
  const pageSize = 5;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const visibleFindings = findings.slice(start, start + pageSize);

  useEffect(() => {
    setPage(1);
  }, [query, findings.length]);

  return (
    <section className="panel table-panel findings-table">
      <div className="table-head">
        <h2>Findings</h2>
        <div className="table-actions">
          <label className="search">
            <Search size={16} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings" />
          </label>
          {jsonHref && <a className="secondary-button" href={jsonHref} target="_blank">Export JSON</a>}
        </div>
      </div>
      <table>
        <thead>
          <tr><th>Severity</th><th>Scanner</th><th>Rule</th><th>File</th><th>Line</th><th>Remediation</th><th /></tr>
        </thead>
        <tbody>
          {visibleFindings.length === 0 && (
            <tr>
              <td colSpan={7} className="empty-cell">No findings loaded yet.</td>
            </tr>
          )}
          {visibleFindings.map((finding) => (
            <tr key={finding.finding_id}>
              <td><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span></td>
              <td>{finding.scanner}</td>
              <td>{finding.rule_id ?? finding.cve ?? "-"}</td>
              <td>{finding.file ?? "-"}</td>
              <td>{finding.line_start ?? "-"}</td>
              <td>{finding.remediation ?? "Review scanner guidance and apply a secure fix."}</td>
              <td><ChevronRight size={16} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="table-footer">
        <span>
          {findings.length === 0
            ? "Showing 0 findings"
            : `Showing ${start + 1} to ${Math.min(start + pageSize, findings.length)} of ${findings.length} findings`}
        </span>
        <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={setPage} />
      </div>
    </section>
  );
}

function Pagination({ currentPage, totalPages, onPageChange }: { currentPage: number; totalPages: number; onPageChange: (page: number) => void }) {
  const pages = paginationRange(currentPage, totalPages);
  return (
    <nav className="pagination" aria-label="Findings pagination">
      <button disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)} aria-label="Previous page">
        <ChevronRight className="flip" size={17} />
      </button>
      {pages.map((page, index) =>
        page === "..."
          ? <span key={`ellipsis-${index}`}>...</span>
          : (
            <button key={page} className={page === currentPage ? "active" : ""} onClick={() => onPageChange(page)}>
              {page}
            </button>
          )
      )}
      <button disabled={currentPage === totalPages} onClick={() => onPageChange(currentPage + 1)} aria-label="Next page">
        <ChevronRight size={17} />
      </button>
    </nav>
  );
}

function ScannerStatus({ report, job }: { report: ScanReport | null; job: ScanJob | null }) {
  const scanners = report?.scanners ?? [
    { scanner: "OpenGrep", status: job ? job.status : "Idle", version: "", raw_finding_count: 0, parsed_finding_count: 0, dropped_finding_count: 0, duration_seconds: 0 },
    { scanner: "Trivy", status: job ? job.status : "Idle", version: "", raw_finding_count: 0, parsed_finding_count: 0, dropped_finding_count: 0, duration_seconds: 0 }
  ];
  return (
    <section className="panel side-panel">
      <h2>Scanner Status</h2>
      {scanners.map((scanner) => (
        <div className="scanner-card" key={scanner.scanner}>
          <div className="scanner-title">
            <CheckCircle2 size={24} />
            <div>
              <strong>{scanner.scanner}</strong>
              <span>{scanner.version || "Waiting"}</span>
            </div>
            <em className={statusClass(scanner.status)}>{scanner.status}</em>
          </div>
          <dl>
            <dt>Raw</dt><dd>{scanner.raw_finding_count}</dd>
            <dt>Parsed</dt><dd>{scanner.parsed_finding_count}</dd>
            <dt>Dropped</dt><dd>{scanner.dropped_finding_count}</dd>
          </dl>
        </div>
      ))}
    </section>
  );
}

function ReportPanel({ job, report }: { job: ScanJob | null; report: ScanReport | null }) {
  const reports = job?.reports ?? {
    json: "/api/reports/latest/json/",
    html: "/api/reports/latest/html/",
    sarif: "/api/reports/latest/sarif/",
    pdf: "/api/reports/latest/pdf/"
  };
  const hasReport = Boolean(report) || Boolean(job && finalStatuses.includes(job.status));
  return (
    <section className="panel side-panel">
      <h2>Report</h2>
      <dl className="report-list">
        <dt>Scan ID</dt><dd>{job?.id ?? report?.metadata.scan_id ?? "-"}</dd>
        <dt>Status</dt><dd>{job?.status ?? report?.status ?? "READY"}</dd>
        <dt>Target</dt><dd>{job?.target ?? report?.metadata.target ?? "-"}</dd>
        <dt>Duration</dt><dd>{report?.metadata.duration_seconds ? `${report.metadata.duration_seconds}s` : "-"}</dd>
        <dt>Integrity</dt><dd>{integrityLabel(job ?? report)}</dd>
      </dl>
      {hasReport && (
        <div className="report-actions">
          <a href={reports.json} target="_blank">Export JSON</a>
          <a href={reports.html} target="_blank">Open HTML Report</a>
          <a href={reports.sarif} target="_blank">SARIF</a>
          <a href={reports.pdf} target="_blank">Download PDF</a>
        </div>
      )}
      {job?.error && (
        <div className="error-banner">
          <AlertTriangle size={16} />
          {job.error}
        </div>
      )}
    </section>
  );
}

function NavButton({ active, icon, children, onClick }: { active: boolean; icon: ReactNode; children: ReactNode; onClick: () => void }) {
  return (
    <button className={active ? "active" : ""} onClick={onClick}>
      {icon}
      {children}
    </button>
  );
}

function TabButton({ active, icon, children, onClick }: { active: boolean; icon: ReactNode; children: ReactNode; onClick: () => void }) {
  return (
    <button className={active ? "selected" : ""} onClick={onClick}>
      {icon}
      {children}
    </button>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  return <div className="metric">{icon}<div><span>{label}</span><strong>{value}</strong></div></div>;
}

function SummaryTile({ label, value, tone }: { label: string; value: string | number; tone: string }) {
  return (
    <section className={`summary-tile ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

function InfoBlock({ title, value, detail }: { title: string; value: string; detail: string }) {
  return (
    <article className="info-block">
      <span>{title}</span>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

function validateScanInput(targetType: TargetType, githubUrl: string, localPath: string, files: File[]): string {
  if (targetType === "github" && !githubUrl.trim()) return "Enter a GitHub repository URL.";
  if (targetType === "local_path" && !localPath.trim()) return "Enter a local file or folder path.";
  if ((targetType === "file" || targetType === "folder") && files.length === 0) return "Choose a file or folder before starting the scan.";
  return "";
}

function paginationRange(currentPage: number, totalPages: number): Array<number | "..."> {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const pages = new Set<number>([1, totalPages, currentPage, currentPage - 1, currentPage + 1]);
  const ordered = Array.from(pages)
    .filter((page) => page >= 1 && page <= totalPages)
    .sort((left, right) => left - right);

  const result: Array<number | "..."> = [];
  for (const page of ordered) {
    const previous = result[result.length - 1];
    if (typeof previous === "number" && page - previous > 1) {
      result.push("...");
    }
    result.push(page);
  }
  return result;
}

function integrityLabel(source: { integrity?: ScanJob["integrity"] } | null): string {
  if (!source?.integrity) return "-";
  const raw = source.integrity.scanner_raw_finding_count ?? 0;
  const parsed = source.integrity.scanner_parsed_finding_count ?? 0;
  const dropped = source.integrity.dropped_finding_count ?? 0;
  return `raw ${raw} / parsed ${parsed} / dropped ${dropped}`;
}

function pageTitle(page: Page): string {
  return {
    dashboard: "Dashboard",
    "new-scan": "New Scan",
    reports: "Reports",
    rules: "Rules",
    settings: "Settings"
  }[page];
}

function pageSubtitle(page: Page): string {
  return {
    dashboard: "Track scanner health, latest coverage, and scan activity.",
    "new-scan": "Run SAST, dependency, secret, and misconfiguration analysis from one workflow.",
    reports: "Open previous scan reports and download machine-readable outputs.",
    rules: "Review the rule sources used by OpenGrep and Trivy.",
    settings: "Runtime integration points for the React UI and Django API."
  }[page];
}

function statusClass(status: string): string {
  const normalized = status.toLowerCase();
  if (normalized === "success") return "success";
  if (normalized === "failed" || normalized === "error") return "failed";
  if (normalized === "partial") return "partial";
  if (normalized === "running" || normalized === "queued") return "running";
  if (normalized === "ready" || normalized === "idle") return "ready";
  return "info";
}
