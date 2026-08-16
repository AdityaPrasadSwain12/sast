import { ChangeEvent, DragEvent as ReactDragEvent, FormEvent, KeyboardEvent as ReactKeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowRight,
  BarChart3,
  Braces,
  Bug,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  CircleDot,
  Clock3,
  CloudUpload,
  Code2,
  Database,
  Download,
  ExternalLink,
  FileCheck2,
  FileCode2,
  FileJson,
  Files,
  Folder,
  FolderOpen,
  Gauge,
  Github,
  HardDrive,
  Home,
  Layers3,
  Link,
  ListChecks,
  LockKeyhole,
  Loader2,
  PackageSearch,
  PanelLeftClose,
  PanelLeftOpen,
  Play,
  RefreshCcw,
  RotateCcw,
  ScanLine,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  TerminalSquare,
  Timer,
  TrendingUp,
  UploadCloud,
  X
} from "lucide-react";
import {
  createLocalPathScan,
  createUploadScan,
  createUrlScan,
  getLatestReport,
  getReport,
  getScan,
  listScans,
  resolveApiUrl
} from "./api";
import RulesPage from "./RulesPage";
import type { Finding, ScanJob, ScanReport, TargetType } from "./types";

type Page = "dashboard" | "new-scan" | "reports" | "rules" | "settings";

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const finalStatuses = ["SUCCESS", "FAILED", "PARTIAL", "ERROR"];
const reportStatuses = ["SUCCESS", "FAILED", "PARTIAL", "ERROR"];
const severityColors: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#3b82f6",
  UNKNOWN: "#94a3b8"
};

export default function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem("sast-scan-sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const [targetType, setTargetType] = useState<TargetType>("github");
  const [githubUrl, setGithubUrl] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [singleFile, setSingleFile] = useState<File | null>(null);
  const [folderFiles, setFolderFiles] = useState<File[]>([]);
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");
  const [pollError, setPollError] = useState("");
  const [dashboardReport, setDashboardReport] = useState<ScanReport | null>(null);
  const [dashboardRefreshing, setDashboardRefreshing] = useState(false);
  const [dashboardLoaded, setDashboardLoaded] = useState(false);
  const [dashboardError, setDashboardError] = useState("");
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [historyError, setHistoryError] = useState("");
  const [historyUpdatedAt, setHistoryUpdatedAt] = useState<Date | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const submissionGuardRef = useRef(false);
  const reportRequestRef = useRef(0);
  const historyRequestRef = useRef(0);
  const isBusy = job?.status === "QUEUED" || job?.status === "RUNNING";

  useEffect(() => {
    void refreshDashboard();
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("sast-scan-sidebar-collapsed", String(sidebarCollapsed));
    } catch {
      // Storage can be unavailable in private or restricted browser contexts.
    }
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (!job || !isBusy) return;
    const pollingJobId = job.id;
    let cancelled = false;
    let timer = 0;

    const poll = async () => {
      try {
        const next = await getScan(pollingJobId);
        if (cancelled) return;
        setPollError("");
        setJob(next);
        if (finalStatuses.includes(next.status)) {
          await loadReport(next, true);
          await refreshHistory();
          return;
        }
      } catch (statusError) {
        if (!cancelled) setPollError(statusError instanceof Error ? statusError.message : "Unable to refresh scan status");
      }
      if (!cancelled) timer = window.setTimeout(poll, 2500);
    };

    timer = window.setTimeout(poll, 2500);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [job?.id, isBusy]);

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

  async function refreshHistory(): Promise<boolean> {
    const requestId = ++historyRequestRef.current;
    try {
      const nextHistory = await listScans();
      if (requestId !== historyRequestRef.current) return true;
      setHistory(nextHistory);
      setHistoryError("");
      setHistoryUpdatedAt(new Date());
      return true;
    } catch {
      if (requestId !== historyRequestRef.current) return false;
      setHistoryError("Scan history could not be refreshed. Existing results are still shown.");
      return false;
    }
  }

  async function refreshDashboard() {
    const historyRequestId = ++historyRequestRef.current;
    setDashboardRefreshing(true);
    setDashboardError("");
    const [jobsResult, reportResult] = await Promise.allSettled([listScans(), getLatestReport()]);

    if (jobsResult.status === "fulfilled" && historyRequestId === historyRequestRef.current) {
      setHistory(jobsResult.value);
      setHistoryError("");
      setHistoryUpdatedAt(new Date());
    } else if (jobsResult.status === "rejected" && historyRequestId === historyRequestRef.current) {
      setHistoryError("Scan history is unavailable. Check the API connection and try again.");
    }
    if (reportResult.status === "fulfilled") {
      setDashboardReport(reportResult.value);
    } else if (jobsResult.status === "fulfilled") {
      setDashboardReport(null);
    }

    const failures = [jobsResult, reportResult].filter((result) => result.status === "rejected").length;
    if (failures) {
      setDashboardError(failures === 2 ? "Dashboard data is unavailable. Check the API connection and try again." : "Some dashboard data could not be refreshed.");
    }
    setDashboardLoaded(true);
    setDashboardRefreshing(false);
  }

  async function loadReport(nextJob: ScanJob, updateDashboard = false) {
    const requestId = ++reportRequestRef.current;
    setJob(nextJob);
    setReportError("");
    if (!reportStatuses.includes(nextJob.status)) {
      setReport(null);
      setReportLoading(false);
      return;
    }
    setReportLoading(true);
    try {
      const nextReport = await getReport(nextJob);
      if (requestId !== reportRequestRef.current) return;
      if (!reportMatchesJob(nextReport, nextJob)) throw new Error("The returned report does not belong to this scan job.");
      setReport(nextReport);
      if (updateDashboard) {
        setDashboardReport(nextReport);
        setDashboardError("");
      }
    } catch (loadError) {
      if (requestId !== reportRequestRef.current) return;
      setReport(null);
      setReportError(loadError instanceof Error ? loadError.message : "The detailed report could not be loaded.");
      if (updateDashboard) {
        setDashboardReport(null);
        setDashboardError("The scan completed, but its detailed report could not be loaded.");
      }
    } finally {
      if (requestId === reportRequestRef.current) setReportLoading(false);
    }
  }

  async function startScan() {
    if (submissionGuardRef.current || isBusy) return;
    setError("");
    const validation = validateScanInput(targetType, githubUrl, localPath, singleFile, folderFiles, zipFile);
    if (validation) {
      setError(validation);
      return;
    }

    submissionGuardRef.current = true;
    setIsSubmitting(true);
    try {
      const created =
        targetType === "github"
          ? await createUrlScan(githubUrl.trim())
          : targetType === "local_path"
            ? await createLocalPathScan(localPath.trim())
            : await createUploadScan(targetType, targetType === "file" ? [singleFile as File] : targetType === "zip" ? [zipFile as File] : folderFiles);
      reportRequestRef.current += 1;
      setReport(null);
      setReportError("");
      setReportLoading(false);
      setPollError("");
      setQuery("");
      setJob(created);
      setPage("new-scan");
      await refreshHistory();
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Unable to start scan");
    } finally {
      submissionGuardRef.current = false;
      setIsSubmitting(false);
    }
  }

  function selectSingleFile(file: File | null) {
    setError("");
    if (file && isArchiveName(file.name)) {
      setError(singleFile
        ? `Archive rejected. ${singleFile.name} remains selected; use ZIP archive for .zip files or extract the archive and choose Project Folder.`
        : "Use ZIP archive for .zip files, or extract the archive and choose Project Folder.");
      return;
    }
    setSingleFile(file);
  }

  function selectFolder(files: File[]) {
    setError("");
    setFolderFiles(files);
  }

  function selectZipFile(file: File | null) {
    setError("");
    if (file && !file.name.toLowerCase().endsWith(".zip")) {
      setError("Choose a .zip archive. Other archive formats are not supported yet.");
      return;
    }
    setZipFile(file);
  }

  function resetScanWorkspace() {
    if (isBusy || isSubmitting) return;
    reportRequestRef.current += 1;
    setTargetType("github");
    setGithubUrl("");
    setLocalPath("");
    setSingleFile(null);
    setFolderFiles([]);
    setZipFile(null);
    setJob(null);
    setReport(null);
    setReportError("");
    setPollError("");
    setError("");
    setQuery("");
  }

  async function retryScanStatus() {
    if (!job) return;
    setPollError("");
    try {
      const next = await getScan(job.id);
      setJob(next);
      if (finalStatuses.includes(next.status)) {
        await loadReport(next, true);
        await refreshHistory();
      }
    } catch (statusError) {
      setPollError(statusError instanceof Error ? statusError.message : "Unable to refresh scan status");
    }
  }

  const dashboardShellJobs = Array.from(new Map([...history, ...(job ? [job] : [])].map((item) => [item.id, item])).values())
    .sort((left, right) => safeDate(right.created_at) - safeDate(left.created_at));
  const dashboardActiveStatus = dashboardShellJobs.find((item) => item.status === "RUNNING" || item.status === "QUEUED")?.status;
  const dashboardLatestStatus = dashboardShellJobs.find((item) => finalStatuses.includes(item.status))?.status;
  const shellStatus = page === "dashboard"
    ? dashboardActiveStatus ?? dashboardLatestStatus ?? dashboardReport?.status ?? "READY"
    : job?.status ?? report?.status ?? "READY";

  return (
    <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <aside className={`sidebar ${sidebarCollapsed ? "collapsed" : ""}`} aria-label="Application sidebar">
        <div className="brand">
          <Shield size={28} />
          <span>SAST Scan</span>
        </div>
        <button
          type="button"
          className="sidebar-collapse-toggle"
          onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
          aria-controls="desktop-primary-navigation"
          aria-expanded={!sidebarCollapsed}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
        </button>
        <nav id="desktop-primary-navigation" className="nav" aria-label="Primary navigation">
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
        <div className="sidebar-card" title="Scanner stack: OpenGrep and Trivy">
          <Database className="sidebar-stack-icon" size={20} aria-hidden="true" />
          <div className="sidebar-card-copy">
            <span>Scanner Stack</span>
            <strong>OpenGrep + Trivy</strong>
            <small>Containerized execution</small>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <h1>{pageTitle(page)}</h1>
            <p>{pageSubtitle(page)}</p>
          </div>
          <div className="topbar-actions">
            {page === "dashboard" && (
              <>
                <button type="button" className="topbar-icon-button" onClick={() => refreshDashboard()} disabled={dashboardRefreshing} aria-label="Refresh dashboard" title="Refresh dashboard">
                  <RefreshCcw className={dashboardRefreshing ? "spin" : ""} size={17} />
                </button>
                <button type="button" className="topbar-primary-button" onClick={() => setPage("new-scan")}>
                  <Play size={17} /> New Scan
                </button>
              </>
            )}
            <div className={`status-pill ${statusClass(shellStatus)}`}>{shellStatus}</div>
          </div>
        </header>

        <nav className="mobile-nav" aria-label="Mobile navigation">
          <NavButton active={page === "dashboard"} icon={<Home size={17} />} onClick={() => setPage("dashboard")}>Dashboard</NavButton>
          <NavButton active={page === "new-scan"} icon={<Gauge size={17} />} onClick={() => setPage("new-scan")}>New Scan</NavButton>
          <NavButton active={page === "reports"} icon={<FileJson size={17} />} onClick={() => setPage("reports")}>Reports</NavButton>
          <NavButton active={page === "rules"} icon={<Code2 size={17} />} onClick={() => setPage("rules")}>Rules</NavButton>
          <NavButton active={page === "settings"} icon={<Settings size={17} />} onClick={() => setPage("settings")}>Settings</NavButton>
        </nav>

        {page === "dashboard" && (
          <DashboardPage
            job={job}
            report={dashboardReport}
            history={history}
            refreshing={dashboardRefreshing}
            loaded={dashboardLoaded}
            dashboardError={dashboardError}
            onRefresh={() => refreshDashboard()}
            onNewScan={() => setPage("new-scan")}
            onOpenReports={() => setPage("reports")}
            onViewFindings={(item, latestReport) => {
              if (item) setJob(item);
              setReport(latestReport);
              setPage("new-scan");
            }}
            onOpenScan={async (item) => {
              await loadReport(item);
              setPage("new-scan");
            }}
          />
        )}
        {page === "new-scan" && (
          <ScanPage
            targetType={targetType}
            setTargetType={setTargetType}
            githubUrl={githubUrl}
            setGithubUrl={setGithubUrl}
            localPath={localPath}
            setLocalPath={setLocalPath}
            singleFile={singleFile}
            folderFiles={folderFiles}
            zipFile={zipFile}
            selectSingleFile={selectSingleFile}
            selectFolder={selectFolder}
            selectZipFile={selectZipFile}
            clearError={() => setError("")}
            setInputError={setError}
            startScan={startScan}
            isBusy={isBusy}
            isSubmitting={isSubmitting}
            error={error}
            job={job}
            report={report}
            reportLoading={reportLoading}
            reportError={reportError}
            pollError={pollError}
            findings={findings}
            query={query}
            setQuery={setQuery}
            onRetryStatus={retryScanStatus}
            onRetryReport={() => job && loadReport(job)}
            onStartAnother={resetScanWorkspace}
            onOpenDashboard={() => setPage("dashboard")}
            onOpenReports={() => setPage("reports")}
          />
        )}
        {page === "reports" && (
          <ReportsPage
            history={history}
            historyLoaded={dashboardLoaded}
            historyError={historyError}
            historyUpdatedAt={historyUpdatedAt}
            currentJob={job}
            onRefresh={refreshHistory}
            onNewScan={() => setPage("new-scan")}
            onReviewFindings={(item, selectedReport) => {
              setJob(item);
              setReport(selectedReport);
              setQuery("");
              setPage("new-scan");
            }}
          />
        )}
        {page === "rules" && <RulesPage onNewScan={() => setPage("new-scan")} />}
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
  singleFile: File | null;
  folderFiles: File[];
  zipFile: File | null;
  selectSingleFile: (file: File | null) => void;
  selectFolder: (files: File[]) => void;
  selectZipFile: (file: File | null) => void;
  clearError: () => void;
  setInputError: (message: string) => void;
  startScan: () => void;
  isBusy: boolean;
  isSubmitting: boolean;
  error: string;
  job: ScanJob | null;
  report: ScanReport | null;
  reportLoading: boolean;
  reportError: string;
  pollError: string;
  findings: Finding[];
  query: string;
  setQuery: (value: string) => void;
  onRetryStatus: () => void;
  onRetryReport: () => void;
  onStartAnother: () => void;
  onOpenDashboard: () => void;
  onOpenReports: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);
  const zipInputRef = useRef<HTMLInputElement | null>(null);
  const executionHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const coherentReport = props.job && props.report && reportMatchesJob(props.report, props.job) ? props.report : null;
  const folderBytes = props.folderFiles.reduce((total, file) => total + file.size, 0);
  const folderArchives = props.folderFiles.filter((file) => isArchiveName(file.name)).length;
  const folderRoot = folderRootName(props.folderFiles);
  const folderExtensions = summarizeFileExtensions(props.folderFiles);
  const folderFileTypeCount = countFileExtensions(props.folderFiles);
  const submissionBusy = props.isBusy || props.isSubmitting;

  useEffect(() => {
    if (props.job?.id) executionHeadingRef.current?.focus();
  }, [props.job?.id]);

  function chooseSource(next: TargetType) {
    if (props.isSubmitting) return;
    props.clearError();
    props.setTargetType(next);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void props.startScan();
  }

  function onSingleFileChange(event: ChangeEvent<HTMLInputElement>) {
    props.selectSingleFile(event.target.files?.[0] ?? null);
    event.target.value = "";
  }

  function onFolderChange(event: ChangeEvent<HTMLInputElement>) {
    props.selectFolder(Array.from(event.target.files ?? []));
    event.target.value = "";
  }

  function onZipFileChange(event: ChangeEvent<HTMLInputElement>) {
    props.selectZipFile(event.target.files?.[0] ?? null);
    event.target.value = "";
  }

  function acceptDroppedFile(event: ReactDragEvent<HTMLElement>) {
    event.preventDefault();
    setDragging(false);
    if (props.isSubmitting) return;
    if (event.dataTransfer.files.length !== 1) {
      props.setInputError("Choose exactly one source file. Use Project Folder when you need to scan multiple files.");
      return;
    }
    props.selectSingleFile(event.dataTransfer.files?.[0] ?? null);
  }

  function openFilePicker(event: ReactKeyboardEvent<HTMLElement>) {
    if (props.isSubmitting) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInputRef.current?.click();
    }
  }

  return (
    <section className="new-scan-page">
      <form className="scan-create-flow" onSubmit={submit} noValidate>
        <section className={`scan-hero ${props.targetType === "github" ? "github-active" : "alternate-active"}`}>
          <div className="scan-hero-main">
            <span className="scan-kicker"><ShieldCheck size={15} /> New security assessment</span>
            <h2>Scan a repository before it ships.</h2>
            <p>Run source, dependency, secret, and configuration checks through one focused security workflow.</p>

            {props.targetType === "github" ? (
              <div className="github-scan-composer">
                <label className="sr-only" htmlFor="github-repository-url">Public GitHub repository URL</label>
                <Github size={21} aria-hidden="true" />
                <input
                  id="github-repository-url"
                  type="url"
                  value={props.githubUrl}
                  onChange={(event) => { props.setGithubUrl(event.target.value); props.clearError(); }}
                  disabled={props.isSubmitting}
                  placeholder="https://github.com/owner/repository"
                  aria-describedby="github-scan-help github-scan-error"
                  aria-invalid={Boolean(props.error)}
                  autoComplete="url"
                />
                <button type="submit" disabled={submissionBusy} aria-busy={props.isSubmitting}>
                  {props.isSubmitting ? <Loader2 className="spin" size={18} /> : <ScanLine size={18} />}
                  {props.isSubmitting ? "Starting…" : "Scan repository"}
                </button>
              </div>
            ) : (
              <div className="scan-source-return">
                <div className="scan-source-return-icon">{sourceIcon(props.targetType)}</div>
                <div><span>Alternative source selected</span><strong>{sourceLabel(props.targetType)}</strong></div>
                <button type="button" disabled={props.isSubmitting} onClick={() => chooseSource("github")}><Github size={16} /> Use GitHub URL</button>
              </div>
            )}

            {props.targetType === "github" && (
              <div className="github-scan-meta" id="github-scan-help">
                <span><LockKeyhole size={14} /> Public repositories</span>
                <span><CircleDot size={14} /> Default branch</span>
                <button type="button" disabled={props.isSubmitting} onClick={() => { props.setGithubUrl("https://github.com/OWASP/NodeGoat"); props.clearError(); }}>Use sample repository</button>
              </div>
            )}
            {props.targetType === "github" && props.error && <div className="scan-inline-error" id="github-scan-error" role="alert"><AlertTriangle size={17} />{props.error}</div>}
          </div>

          <div className="scan-capability-board" aria-label="Security checks included">
            <span className="scan-capability-title">One scan, broad coverage</span>
            <div className="scan-capability-grid">
              <article><Braces size={19} /><div><strong>Source code</strong><span>OpenGrep SAST</span></div></article>
              <article><PackageSearch size={19} /><div><strong>Dependencies</strong><span>Known vulnerabilities</span></div></article>
              <article><LockKeyhole size={19} /><div><strong>Secrets</strong><span>Credential exposure</span></div></article>
              <article><ListChecks size={19} /><div><strong>Configuration</strong><span>IaC and config risks</span></div></article>
            </div>
          </div>
        </section>

        <fieldset className="scan-source-section">
          <legend>Or scan another source</legend>
          <p>Choose the source that is available to you. Only the selected source will be submitted.</p>
          <div className="scan-source-grid">
            <SourceChoiceCard
              active={props.targetType === "file"}
              icon={<FileCode2 size={22} />}
              title="Source file"
              detail="Scan one code or configuration file"
              meta="Upload from this device"
              disabled={props.isSubmitting}
              onClick={() => chooseSource("file")}
            />
            <SourceChoiceCard
              active={props.targetType === "folder"}
              icon={<FolderOpen size={22} />}
              title="Project folder"
              detail="Scan a complete local codebase"
              meta="Preserves relative paths"
              disabled={props.isSubmitting}
              onClick={() => chooseSource("folder")}
            />
            <SourceChoiceCard
              active={props.targetType === "local_path"}
              icon={<HardDrive size={22} />}
              title="Scanner workspace"
              detail="Use a path on the API host"
              meta="Advanced local setup"
              disabled={props.isSubmitting}
              onClick={() => chooseSource("local_path")}
            />
            <SourceChoiceCard
              active={props.targetType === "zip"}
              icon={<Archive size={22} />}
              title="ZIP archive"
              detail="Upload a packaged project"
              meta="Extracts safely before scan"
              disabled={props.isSubmitting}
              onClick={() => chooseSource("zip")}
            />
          </div>
        </fieldset>

        {props.targetType !== "github" && (
          <section className="scan-config-grid">
            <div className="scan-config-card">
              <header>
                <div className="scan-config-icon">{sourceIcon(props.targetType)}</div>
                <div><span>Selected source</span><h3>{sourceLabel(props.targetType)}</h3></div>
              </header>

              {props.targetType === "file" && (
                <>
                  <input ref={fileInputRef} id="scan-file-input" className="visually-hidden-input" type="file" tabIndex={-1} onChange={onSingleFileChange} aria-label="Choose source file" disabled={props.isSubmitting} />
                  <div
                    className={`scan-dropzone ${dragging ? "dragging" : ""}`}
                    role="button"
                    tabIndex={0}
                    aria-disabled={props.isSubmitting}
                    onClick={() => { if (!props.isSubmitting) fileInputRef.current?.click(); }}
                    onKeyDown={openFilePicker}
                    onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                    onDragOver={(event) => event.preventDefault()}
                    onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setDragging(false); }}
                    onDrop={acceptDroppedFile}
                    aria-describedby="file-upload-help"
                  >
                    <div><UploadCloud size={27} /></div>
                    <strong>{props.singleFile ? "Replace selected file" : "Drop a source file here"}</strong>
                    <span>or click to browse this device</span>
                  </div>
                  <p className="scan-field-help" id="file-upload-help">Use ZIP archive for packaged .zip projects. Extract other archive formats before scanning.</p>
                  {props.singleFile && (
                    <div className="selected-upload">
                      <div><FileCheck2 size={20} /></div>
                      <span><strong>{props.singleFile.name}</strong><small>{formatFileSize(props.singleFile.size)} · Ready to upload</small></span>
                      <button type="button" disabled={props.isSubmitting} onClick={() => props.selectSingleFile(null)} aria-label={`Remove ${props.singleFile.name}`}><X size={17} /></button>
                    </div>
                  )}
                </>
              )}

              {props.targetType === "folder" && (
                <>
                  <input ref={folderInputRef} id="scan-folder-input" className="visually-hidden-input" type="file" tabIndex={-1} multiple webkitdirectory="true" onChange={onFolderChange} aria-label="Choose project folder" disabled={props.isSubmitting} />
                  {props.folderFiles.length ? (
                    <div className="selected-folder">
                      <div className="selected-folder-head">
                        <div><FolderOpen size={22} /></div>
                        <span><strong>{folderRoot || "Selected project"}</strong><small>{props.folderFiles.length.toLocaleString()} files · {formatFileSize(folderBytes)}</small></span>
                        <button type="button" disabled={props.isSubmitting} onClick={() => folderInputRef.current?.click()}><RotateCcw size={15} /> Replace</button>
                      </div>
                      <div className="folder-selection-stats">
                        <span><strong>{props.folderFiles.length.toLocaleString()}</strong> Files</span>
                        <span><strong>{folderFileTypeCount}</strong> File types</span>
                        <span><strong>{folderArchives}</strong> Archives</span>
                      </div>
                      {folderExtensions.length > 0 && <div className="folder-extension-list">{folderExtensions.map((extension) => <span key={extension}>{extension}</span>)}</div>}
                      {folderArchives > 0 && <p className="scan-upload-warning"><AlertTriangle size={15} />Archive files inside folders are scanned as files, not extracted. Use ZIP archive for one packaged project.</p>}
                    </div>
                  ) : (
                    <button type="button" className="folder-picker" disabled={props.isSubmitting} onClick={() => folderInputRef.current?.click()}>
                      <div><CloudUpload size={27} /></div><span><strong>Choose a project folder</strong><small>Relative paths are preserved for accurate findings</small></span><ArrowRight size={19} />
                    </button>
                  )}
                </>
              )}

              {props.targetType === "zip" && (
                <>
                  <input ref={zipInputRef} id="scan-zip-input" className="visually-hidden-input" type="file" tabIndex={-1} accept=".zip,application/zip,application/x-zip-compressed" onChange={onZipFileChange} aria-label="Choose ZIP archive" disabled={props.isSubmitting} />
                  <div
                    className={`scan-dropzone ${dragging ? "dragging" : ""}`}
                    role="button"
                    tabIndex={0}
                    aria-disabled={props.isSubmitting}
                    onClick={() => { if (!props.isSubmitting) zipInputRef.current?.click(); }}
                    onKeyDown={(event) => {
                      if (props.isSubmitting) return;
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        zipInputRef.current?.click();
                      }
                    }}
                  >
                    <div><Archive size={27} /></div>
                    <strong>{props.zipFile ? "Replace selected ZIP" : "Choose a ZIP archive"}</strong>
                    <span>The backend extracts it safely, then scans the project folder</span>
                  </div>
                  <p className="scan-field-help">Supported now: .zip only. The backend blocks unsafe paths, oversized archives, and extraction bombs.</p>
                  {props.zipFile && (
                    <div className="selected-upload">
                      <div><Archive size={20} /></div>
                      <span><strong>{props.zipFile.name}</strong><small>{formatFileSize(props.zipFile.size)} · Ready to extract and scan</small></span>
                      <button type="button" disabled={props.isSubmitting} onClick={() => props.selectZipFile(null)} aria-label={`Remove ${props.zipFile.name}`}><X size={17} /></button>
                    </div>
                  )}
                </>
              )}

              {props.targetType === "local_path" && (
                <label className="scan-path-field" htmlFor="scanner-workspace-path">
                  <span>Path on the scanner API host</span>
                  <div><TerminalSquare size={18} /><input id="scanner-workspace-path" value={props.localPath} onChange={(event) => { props.setLocalPath(event.target.value); props.clearError(); }} placeholder="Path to a file or project inside the scanner workspace" aria-describedby="workspace-path-help" aria-invalid={Boolean(props.error)} disabled={props.isSubmitting} /></div>
                  <small id="workspace-path-help">This path is resolved by the backend service, not from the computer running your browser.</small>
                </label>
              )}

              {props.error && <div className="scan-inline-error" role="alert"><AlertTriangle size={17} />{props.error}</div>}
              <button className="scan-submit-button" type="submit" disabled={submissionBusy} aria-busy={props.isSubmitting}>
                {props.isSubmitting ? <Loader2 className="spin" size={18} /> : <ScanLine size={18} />}
                {props.isSubmitting ? "Starting scan…" : `Scan ${props.targetType === "file" ? "file" : props.targetType === "folder" ? "folder" : props.targetType === "zip" ? "ZIP" : "workspace"}`}
                {!props.isSubmitting && <ArrowRight size={17} />}
              </button>
            </div>

            <aside className="scan-run-card">
              <span className="scan-kicker"><Shield size={14} /> What will run</span>
              <h3>Two engines, one report</h3>
              <div className="scan-run-list">
                <article><div className="opengrep"><Braces size={18} /></div><span><strong>OpenGrep</strong><small>Source-code security rules</small></span><CheckCircle2 size={17} /></article>
                <article><div className="trivy"><PackageSearch size={18} /></div><span><strong>Trivy</strong><small>Dependencies, secrets, and config</small></span><CheckCircle2 size={17} /></article>
              </div>
              <div className="scan-run-note"><LockKeyhole size={16} /><p><strong>Isolated execution</strong><span>The configured container scanners read the submitted workspace and produce unified reports.</span></p></div>
            </aside>
          </section>
        )}
      </form>

      {props.job && (
        <ScanExecutionPanel
          headingRef={executionHeadingRef}
          job={props.job}
          report={coherentReport}
          reportLoading={props.reportLoading}
          reportError={props.reportError}
          pollError={props.pollError}
          onRetryStatus={props.onRetryStatus}
        />
      )}

      {props.job && coherentReport && (
        <ScanResults
          job={props.job}
          report={coherentReport}
          findings={props.findings}
          query={props.query}
          setQuery={props.setQuery}
          onStartAnother={props.onStartAnother}
          onOpenDashboard={props.onOpenDashboard}
          onOpenReports={props.onOpenReports}
        />
      )}

      {props.job && finalStatuses.includes(props.job.status) && !coherentReport && !props.reportLoading && (
        <section className="scan-report-unavailable" role="alert">
          <div><FileJson size={24} /></div>
          <span><strong>Matching detailed report unavailable</strong><p>{props.reportError || "The job finished, but no coherent report for this scan is currently available. Retry without starting another scan."}</p></span>
          <button type="button" onClick={props.onRetryReport}><RefreshCcw size={16} /> Retry report</button>
        </section>
      )}
    </section>
  );
}

function SourceChoiceCard({ active, icon, title, detail, meta, disabled, onClick }: { active: boolean; icon: ReactNode; title: string; detail: string; meta: string; disabled?: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`scan-source-card ${active ? "selected" : ""}`} aria-pressed={active} disabled={disabled} onClick={onClick}>
      <div className="scan-source-card-icon">{icon}</div>
      <span className="scan-source-check">{active ? <CheckCircle2 size={17} /> : <CircleDot size={15} />}</span>
      <strong>{title}</strong>
      <p>{detail}</p>
      <small>{meta}</small>
    </button>
  );
}

function ScanExecutionPanel({ headingRef, job, report, reportLoading, reportError, pollError, onRetryStatus }: {
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  job: ScanJob;
  report: ScanReport | null;
  reportLoading: boolean;
  reportError: string;
  pollError: string;
  onRetryStatus: () => void;
}) {
  const active = job.status === "QUEUED" || job.status === "RUNNING";
  const terminal = finalStatuses.includes(job.status);
  const hasReport = Boolean(report);
  const outcomeIcon = active ? <Loader2 className="spin" size={22} /> : job.status === "SUCCESS" ? <ShieldCheck size={22} /> : <AlertTriangle size={22} />;
  const outcomeTitle = job.status === "QUEUED" ? "Scan accepted and queued" : job.status === "RUNNING" ? "Security assessment in progress" : job.status === "SUCCESS" ? "Assessment complete — policy passed" : job.status === "FAILED" ? "Assessment complete — policy threshold reached" : job.status === "PARTIAL" ? "Assessment complete with incomplete scanner coverage" : "Scan execution failed";

  return (
    <section className={`scan-execution-card ${statusClass(job.status)}`} aria-live="polite" aria-busy={active || reportLoading}>
      <header className="scan-execution-head">
        <div className="scan-execution-status-icon">{outcomeIcon}</div>
        <div>
          <span>Scan execution</span>
          <h2 ref={headingRef} tabIndex={-1}>{outcomeTitle}</h2>
          <p>{job.status === "ERROR" ? "The job ended before all configured work completed." : job.progress_message || statusExplanation(job.status)}</p>
        </div>
        <span className={`badge ${statusClass(job.status)}`}>{job.status}</span>
      </header>

      <div className="scan-lifecycle" aria-label="Scan progress">
        <LifecycleStep state="complete" label="Target accepted" detail="Submission recorded" />
        <LifecycleStep state={job.status === "ERROR" ? "error" : active ? "current" : "complete"} label={job.status === "QUEUED" ? "Waiting for capacity" : "Scanner execution"} detail={job.status === "QUEUED" ? "Queued" : job.status === "ERROR" ? "Failed" : terminal ? "Finished" : "OpenGrep and Trivy"} />
        <LifecycleStep state={reportLoading ? "current" : hasReport ? "complete" : reportError || job.status === "ERROR" ? "error" : "pending"} label="Build report" detail={reportLoading ? "Loading details" : hasReport ? "Report ready" : reportError ? "Load failed" : job.status === "ERROR" ? "Not produced" : "Pending"} />
        <LifecycleStep state={hasReport ? "complete" : "pending"} label="Review findings" detail={hasReport ? `${summaryTotal(report?.summary)} included` : "Available after report"} />
      </div>

      <dl className="scan-job-meta">
        <div><dt>Target</dt><dd title={job.target}>{job.target}</dd></div>
        <div><dt>Job ID</dt><dd title={job.id}>{job.id}</dd></div>
        <div><dt>Started</dt><dd>{job.started_at ? formatDateTime(job.started_at) : "Waiting"}</dd></div>
        <div><dt>Elapsed</dt><dd>{active && job.started_at ? formatLiveDuration(job.started_at) : formatDuration(report?.metadata.duration_seconds ?? jobDuration(job))}</dd></div>
      </dl>

      {active && <div className="scan-indeterminate" aria-hidden="true"><span /></div>}
      {pollError && <div className="scan-inline-error compact" role="alert"><AlertTriangle size={16} /><span>{pollError}</span><button type="button" onClick={onRetryStatus}><RefreshCcw size={15} /> Retry status</button></div>}
      {job.error && <div className="scan-inline-error compact" role="alert"><AlertTriangle size={16} /><span>{job.error}</span></div>}
    </section>
  );
}

function LifecycleStep({ state, label, detail }: { state: "complete" | "current" | "pending" | "error"; label: string; detail: string }) {
  return (
    <div className={`lifecycle-step ${state}`}>
      <div>{state === "complete" ? <CheckCircle2 size={17} /> : state === "current" ? <Loader2 className="spin" size={17} /> : state === "error" ? <AlertTriangle size={17} /> : <CircleDot size={15} />}</div>
      <span><strong>{label}</strong><small>{detail}</small></span>
    </div>
  );
}

function ScanResults({ job, report, findings, query, setQuery, onStartAnother, onOpenDashboard, onOpenReports }: {
  job: ScanJob;
  report: ScanReport;
  findings: Finding[];
  query: string;
  setQuery: (value: string) => void;
  onStartAnother: () => void;
  onOpenDashboard: () => void;
  onOpenReports: () => void;
}) {
  const summary = report.summary ?? {};
  const jobExecutionFailed = job.status === "ERROR";
  const outcomeTone = jobExecutionFailed || report.status === "FAILED" || report.status === "ERROR" ? "failed" : report.status === "SUCCESS" ? "success" : "partial";
  const partialPolicyFailure = report.status === "PARTIAL" && report.policy_failed === true;
  const outcomeHeading = jobExecutionFailed
    ? "Scan job ended with an execution error"
    : report.status === "SUCCESS"
    ? "Policy passed"
    : report.status === "FAILED"
      ? "Policy threshold reached"
      : report.status === "ERROR"
        ? "Scanner execution failed"
      : partialPolicyFailure
        ? "Coverage incomplete and policy threshold reached"
        : "Scanner coverage incomplete";
  const outcomeDetail = jobExecutionFailed
    ? job.error || "A scanner report was generated, but the web scan job did not finish cleanly. Review the report and diagnostics before relying on its coverage."
    : report.status === "ERROR"
    ? "A diagnostic report is available, but the security assessment did not complete successfully. Review each scanner result before relying on coverage."
    : partialPolicyFailure
    ? `One or more scanners were incomplete, and the ${report.policy_fail_on ? `${report.policy_fail_on.toUpperCase()}+` : "configured"} policy threshold was reached by the available findings.`
    : statusExplanation(report.status, report.policy_fail_on);

  return (
    <section className="scan-results" aria-labelledby="scan-results-title">
      <div className="scan-results-heading">
        <div><span className="scan-kicker"><FileCheck2 size={14} /> Assessment report</span><h2 id="scan-results-title">Results for this scan</h2><p>Explore the included findings, coverage, scanner health, and downloadable reports.</p></div>
        <div className="scan-report-actions" aria-label="Export report">
          <a href={resolveApiUrl(job.reports.html)} target="_blank" rel="noreferrer"><ExternalLink size={15} /> HTML</a>
          <a href={resolveApiUrl(job.reports.pdf)} target="_blank" rel="noreferrer"><Download size={15} /> PDF</a>
          <a href={resolveApiUrl(job.reports.json)} target="_blank" rel="noreferrer">JSON</a>
          <a href={resolveApiUrl(job.reports.sarif)} target="_blank" rel="noreferrer">SARIF</a>
        </div>
      </div>

      <div className="scan-result-metrics dashboard-metrics">
        <DashboardMetric icon={<Bug size={17} />} label="Total findings" value={summaryTotal(summary)} detail="Included in this report" tone={outcomeTone} />
        <DashboardMetric icon={<AlertTriangle size={17} />} label="Critical" value={summaryValue(summary, "CRITICAL")} detail="Immediate attention" tone="critical" />
        <DashboardMetric icon={<CircleAlert size={17} />} label="High" value={summaryValue(summary, "HIGH")} detail="Priority remediation" tone="high" />
        <DashboardMetric icon={<Files size={17} />} label="Candidate files" value={formatNumber(report.coverage.files_scanned)} detail="Local coverage census" tone="" />
        <DashboardMetric icon={<Code2 size={17} />} label="Lines counted" value={formatNumber(report.coverage.lines_scanned)} detail="Binary lines excluded" tone="violet" />
        <DashboardMetric icon={<Timer size={17} />} label="Duration" value={formatDuration(report.metadata.duration_seconds)} detail={outcomeDetail} tone={outcomeTone} />
      </div>

      <div className="scan-result-overview">
        <section className={`scan-outcome-card ${outcomeTone}`}>
          <div className="scan-outcome-icon">{!jobExecutionFailed && report.status === "SUCCESS" ? <ShieldCheck size={24} /> : <AlertTriangle size={24} />}</div>
          <div><span>{jobExecutionFailed || report.status === "ERROR" ? "Assessment outcome" : "Policy outcome"}</span><h3>{outcomeHeading}</h3><p>{outcomeDetail}</p></div>
          <dl>
            <div><dt>Job status</dt><dd>{job.status}</dd></div>
            <div><dt>Report status</dt><dd>{report.status}</dd></div>
            <div><dt>Policy</dt><dd>{report.policy_failed === true ? `Failed${report.policy_fail_on ? ` at ${report.policy_fail_on.toUpperCase()}+` : ""}` : report.policy_failed === false ? "Passed" : "Not reported"}</dd></div>
            <div><dt>Integrity</dt><dd>{report.integrity.all_parsed_findings_included === true ? "Reconciled" : report.integrity.all_parsed_findings_included === false ? "Review mismatch" : "Unavailable"}</dd></div>
          </dl>
        </section>

        <section className="dashboard-card scan-scanner-card">
          <DashboardSectionHeader eyebrow="Engine health" title="Scanner execution" description="Per-engine parsing and report integrity." icon={<Activity size={18} />} />
          <ScannerHealthDashboard report={report} />
        </section>
      </div>

      <ScanDiagnostics report={report} />

      <ScanFindingsPanel allFindings={report.findings} findings={findings} query={query} setQuery={setQuery} />

      <div className="scan-results-footer">
        <p><CircleAlert size={15} />Report downloads currently follow the backend's latest-artifact storage model and may be replaced by a later scan.</p>
        <div><button type="button" className="scan-secondary-button" onClick={onOpenDashboard}><Home size={16} /> Dashboard</button><button type="button" className="scan-secondary-button" onClick={onOpenReports}><FileJson size={16} /> Reports</button><button type="button" className="scan-primary-button" onClick={onStartAnother}><RotateCcw size={16} /> Start another scan</button></div>
      </div>
    </section>
  );
}

function ScanDiagnostics({ report }: { report: ScanReport }) {
  const messages = [
    ...(report.errors ?? []).map((message) => ({ tone: "error", message })),
    ...(report.warnings ?? []).map((message) => ({ tone: "warning", message }))
  ];
  if (!messages.length) return null;
  const visible = messages.slice(0, 6);

  return (
    <section className="scan-diagnostics" aria-labelledby="scan-diagnostics-title">
      <header><div><CircleAlert size={18} /><span><strong id="scan-diagnostics-title">Scanner diagnostics</strong><small>{messages.length} {messages.length === 1 ? "message" : "messages"} reported</small></span></div><span className="badge partial">Review</span></header>
      <div>{visible.map((item, index) => <article className={item.tone} key={`${item.tone}-${index}`}><AlertTriangle size={15} /><p>{item.message}</p></article>)}</div>
      {messages.length > visible.length && <footer>{messages.length - visible.length} more diagnostic {messages.length - visible.length === 1 ? "message is" : "messages are"} available in the JSON report.</footer>}
    </section>
  );
}

function ScanFindingsPanel({ allFindings, findings, query, setQuery }: { allFindings: Finding[]; findings: Finding[]; query: string; setQuery: (value: string) => void }) {
  const [severity, setSeverity] = useState("ALL");
  const [scanner, setScanner] = useState("ALL");
  const [category, setCategory] = useState("ALL");
  const [page, setPage] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const pageSize = 10;
  const scanners = Array.from(new Set(allFindings.map((finding) => finding.scanner).filter(Boolean))).sort();
  const categories = Array.from(new Set(allFindings.map((finding) => finding.category).filter(Boolean))).sort();
  const filtered = findings
    .filter((finding) => severity === "ALL" || finding.severity === severity)
    .filter((finding) => scanner === "ALL" || finding.scanner === scanner)
    .filter((finding) => category === "ALL" || finding.category === category)
    .slice()
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || left.title.localeCompare(right.title));
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const visible = filtered.slice(start, start + pageSize);

  useEffect(() => setPage(1), [query, severity, scanner, category, allFindings]);

  useEffect(() => {
    if (!selectedFinding) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeFinding();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [selectedFinding]);

  function openFinding(finding: Finding, trigger: HTMLButtonElement) {
    triggerRef.current = trigger;
    setSelectedFinding(finding);
  }

  function closeFinding() {
    setSelectedFinding(null);
    window.setTimeout(() => triggerRef.current?.focus(), 0);
  }

  return (
    <section className="dashboard-card scan-findings-card">
      <DashboardSectionHeader eyebrow="Remediation workspace" title="All findings" description="Search and filter the normalized findings included in this report." icon={<Bug size={18} />} />
      <div className="scan-findings-toolbar">
        <label className="scan-findings-search"><Search size={16} /><span className="sr-only">Search findings</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search title, rule, CVE, file…" /></label>
        <label><span className="sr-only">Filter severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="ALL">All severities</option>{severityOrder.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label>
        <label><span className="sr-only">Filter scanner</span><select value={scanner} onChange={(event) => setScanner(event.target.value)}><option value="ALL">All scanners</option>{scanners.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
        <label><span className="sr-only">Filter category</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option value="ALL">All categories</option>{categories.map((value) => <option key={value} value={value}>{friendlyCategory(value)}</option>)}</select></label>
        {(query || severity !== "ALL" || scanner !== "ALL" || category !== "ALL") && <button type="button" onClick={() => { setQuery(""); setSeverity("ALL"); setScanner("ALL"); setCategory("ALL"); }}><RotateCcw size={15} /> Clear</button>}
      </div>

      <div className="scan-findings-summary"><strong>{filtered.length.toLocaleString()}</strong><span>{filtered.length === 1 ? "finding matches" : "findings match"} the current view</span></div>
      {visible.length ? (
        <>
          <div className="scan-findings-table-wrap" tabIndex={0} aria-label="Findings table; scroll horizontally if needed">
            <table className="scan-findings-table">
              <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Location</th><th>Scanner</th><th><span className="sr-only">Action</span></th></tr></thead>
              <tbody>{visible.map((finding) => (
                <tr key={finding.finding_id}>
                  <td><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span></td>
                  <td><button type="button" className="finding-title-button" onClick={(event) => openFinding(finding, event.currentTarget)}><strong>{finding.title}</strong><span>{finding.rule_id ?? finding.cve ?? "Scanner finding"}</span></button></td>
                  <td><span className="category-chip">{friendlyCategory(finding.category)}</span></td>
                  <td><span className="finding-location" title={finding.file ?? undefined}>{finding.file ?? "—"}{finding.line_start ? `:${finding.line_start}` : ""}</span></td>
                  <td>{finding.scanner}</td>
                  <td><button type="button" className="row-action" onClick={(event) => openFinding(finding, event.currentTarget)} aria-label={`View details for ${finding.title}`}><ChevronRight size={17} /></button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="scan-findings-mobile">{visible.map((finding) => <button type="button" key={finding.finding_id} onClick={(event) => openFinding(finding, event.currentTarget)}><span><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><span className="category-chip">{friendlyCategory(finding.category)}</span></span><strong>{finding.title}</strong><small>{finding.rule_id ?? finding.cve ?? finding.scanner}</small><em>{finding.file ?? "Location unavailable"}{finding.line_start ? `:${finding.line_start}` : ""}</em></button>)}</div>
          <footer className="scan-findings-footer"><span>Showing {start + 1}–{Math.min(start + pageSize, filtered.length)} of {filtered.length}</span><Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={setPage} label="Finding pages" /></footer>
        </>
      ) : <DashboardMiniEmpty icon={<Search size={24} />} text={allFindings.length ? "No findings match the current filters." : "No findings were included in this report."} positive={!allFindings.length} />}
      {selectedFinding && <FindingDrawer finding={selectedFinding} onClose={closeFinding} />}
    </section>
  );
}

function DashboardPage({
  job,
  report,
  history,
  refreshing,
  loaded,
  dashboardError,
  onRefresh,
  onNewScan,
  onOpenReports,
  onViewFindings,
  onOpenScan
}: {
  job: ScanJob | null;
  report: ScanReport | null;
  history: ScanJob[];
  refreshing: boolean;
  loaded: boolean;
  dashboardError: string;
  onRefresh: () => void;
  onNewScan: () => void;
  onOpenReports: () => void;
  onViewFindings: (job: ScanJob | null, report: ScanReport) => void;
  onOpenScan: (job: ScanJob) => void;
}) {
  const [distributionView, setDistributionView] = useState<"severity" | "category">("severity");
  const [coverageView, setCoverageView] = useState<"languages" | "extensions">("languages");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const findingTriggerRef = useRef<HTMLButtonElement | null>(null);

  const jobs = useMemo(() => {
    const byId = new Map(history.map((item) => [item.id, item]));
    if (job) byId.set(job.id, job);
    return Array.from(byId.values()).sort((left, right) => safeDate(right.created_at) - safeDate(left.created_at));
  }, [history, job]);

  const latestJob = jobs.find((item) => finalStatuses.includes(item.status)) ?? null;
  const activeJob = jobs.find((item) => item.status === "RUNNING" || item.status === "QUEUED") ?? null;
  const snapshotReport = report && (latestJob ? reportMatchesJob(report, latestJob) : jobs.length === 0) ? report : null;
  const hasCompletedSnapshot = Boolean(snapshotReport || latestJob);
  const summary = snapshotReport?.summary ?? latestJob?.summary ?? {};
  const coverage = snapshotReport?.coverage ?? latestJob?.coverage ?? {};
  const findings = snapshotReport?.findings ?? [];
  const scanStatus = latestJob?.status ?? snapshotReport?.status ?? activeJob?.status ?? "READY";
  const target = latestJob?.target ?? snapshotReport?.metadata.target ?? activeJob?.target ?? "No target selected";
  const scanDate = latestJob?.finished_at ?? latestJob?.created_at ?? snapshotReport?.metadata.started_at ?? activeJob?.created_at ?? null;
  const duration = snapshotReport?.metadata.duration_seconds ?? jobDuration(latestJob);
  const totalFindings = summaryTotal(summary);

  const priorityFindings = useMemo(
    () => findings
      .map((finding, index) => ({ finding, index }))
      .sort((left, right) => severityRank(right.finding.severity) - severityRank(left.finding.severity) || left.index - right.index)
      .slice(0, 5)
      .map(({ finding }) => finding),
    [findings]
  );

  const categoryEntries = useMemo(() => buildCategoryEntries(findings), [findings]);
  const severityEntries = severityOrder.map((severity) => ({
    key: severity,
    label: titleCase(severity),
    value: summaryValue(summary, severity),
    color: severityColors[severity]
  }));
  const distributionEntries = distributionView === "severity" ? severityEntries : categoryEntries;
  const coverageSource = coverageView === "languages" ? coverage.languages : snapshotReport?.coverage.extensions;
  const coverageEntries = buildCoverageEntries(coverageSource);
  const alerts = buildDashboardAlerts(snapshotReport, latestJob, dashboardError);

  function openFinding(finding: Finding, trigger: HTMLButtonElement) {
    findingTriggerRef.current = trigger;
    setSelectedFinding(finding);
  }

  function closeFinding() {
    setSelectedFinding(null);
    window.setTimeout(() => findingTriggerRef.current?.focus(), 0);
  }

  useEffect(() => {
    if (!selectedFinding) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeFinding();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [selectedFinding]);

  if (!loaded) {
    return (
      <section className="dashboard-page dashboard-empty-page" aria-busy="true">
        <div className="dashboard-loading-state" role="status">
          <Loader2 className="spin" size={28} />
          <strong>Loading security dashboard</strong>
          <span>Collecting the latest scans, findings, and engine health.</span>
        </div>
      </section>
    );
  }

  if (!report && jobs.length === 0) {
    return (
      <section className="dashboard-page dashboard-empty-page">
        <div className="dashboard-empty-state">
          <div className="dashboard-empty-icon">{dashboardError ? <CircleAlert size={34} /> : <ShieldCheck size={34} />}</div>
          <span className="eyebrow">Security workspace</span>
          <h2>{dashboardError ? "Dashboard data is unavailable" : "No security scans yet"}</h2>
          <p>{dashboardError ? "The application could not load scan history or the latest report. Check the API and try again." : "Run your first source, dependency, secret, and configuration scan to populate this dashboard."}</p>
          {dashboardError && <div className="dashboard-inline-error" role="alert"><CircleAlert size={17} />{dashboardError}</div>}
          <div className="dashboard-empty-actions">
            {dashboardError && <button type="button" className="dashboard-secondary-action" onClick={onRefresh}><RefreshCcw size={17} /> Try Again</button>}
            <button type="button" className="dashboard-primary-action" onClick={onNewScan}><Play size={17} /> Start New Scan</button>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="dashboard-page" aria-busy={refreshing}>
      {activeJob && (
        <div className="dashboard-active-banner" role="status">
          <div className="active-banner-icon"><Loader2 className="spin" size={19} /></div>
          <div>
            <strong>{activeJob.status === "QUEUED" ? "Scan queued" : "Security scan in progress"}</strong>
            <span>{activeJob.progress_message || `Analyzing ${activeJob.target}`}</span>
          </div>
          <span className={`badge ${statusClass(activeJob.status)}`}>{activeJob.status}</span>
        </div>
      )}

      <div className="dashboard-context">
        <div className="dashboard-target">
          <div className="dashboard-target-icon"><ScanLine size={21} /></div>
          <div>
            <span>{hasCompletedSnapshot ? "Latest completed assessment" : activeJob ? "Assessment in progress" : "Security assessment"}</span>
            <strong title={target}>{target}</strong>
          </div>
        </div>
        <div className="dashboard-context-meta">
          <span><Clock3 size={15} />{scanDate ? formatDateTime(scanDate) : "Date unavailable"}</span>
          <span><Layers3 size={15} />{latestJob ? sourceLabel(latestJob.target_type) : report?.metadata.target_kind ?? "Scan"}</span>
          <span><Shield size={15} />Policy: {snapshotReport?.policy_fail_on ?? "HIGH"}+</span>
        </div>
      </div>

      {dashboardError && <div className="dashboard-inline-error" role="alert"><CircleAlert size={17} />{dashboardError}</div>}

      <div className="dashboard-metrics" aria-label="Latest scan summary">
        <DashboardMetric icon={<ShieldCheck size={20} />} label="Security status" value={scanStatus} detail={statusExplanation(scanStatus, snapshotReport?.policy_fail_on)} tone={statusClass(scanStatus)} />
        <DashboardMetric icon={<AlertTriangle size={20} />} label="Critical" value={summaryValue(summary, "CRITICAL")} detail="Fix immediately" tone="critical" />
        <DashboardMetric icon={<Activity size={20} />} label="High" value={summaryValue(summary, "HIGH")} detail="Release blockers" tone="high" />
        <DashboardMetric icon={<Bug size={20} />} label="Total findings" value={totalFindings} detail={`${summaryValue(summary, "MEDIUM")} medium severity`} tone="info" />
        <DashboardMetric icon={<Files size={20} />} label="Discovered coverage" value={formatNumber(coverage.files_scanned)} detail={`${formatNumber(coverage.lines_scanned)} lines`} tone="blue" />
        <DashboardMetric icon={<Clock3 size={20} />} label="Scan duration" value={formatDuration(duration)} detail="Latest assessment" tone="violet" />
      </div>

      <div className="dashboard-split dashboard-risk-grid">
        <section className="dashboard-card trend-card">
          <DashboardSectionHeader eyebrow="Risk analytics" title="Findings trend" description="Severity movement across the latest completed scans." icon={<TrendingUp size={18} />} />
          <RiskTrend jobs={jobs} onOpenScan={onOpenScan} />
        </section>

        <section className="dashboard-card distribution-card">
          <DashboardSectionHeader
            eyebrow="Latest scan"
            title="Finding distribution"
            description="Switch between severity and security category."
            icon={<BarChart3 size={18} />}
            action={
              <div className="dashboard-segmented" role="group" aria-label="Distribution type">
                <button type="button" className={distributionView === "severity" ? "active" : ""} aria-pressed={distributionView === "severity"} onClick={() => setDistributionView("severity")}>Severity</button>
                <button type="button" className={distributionView === "category" ? "active" : ""} aria-pressed={distributionView === "category"} onClick={() => setDistributionView("category")}>Category</button>
              </div>
            }
          />
          <DistributionChart entries={distributionEntries} mode={distributionView} />
        </section>
      </div>

      <div className="dashboard-split dashboard-coverage-grid">
        <section className="dashboard-card coverage-card">
          <DashboardSectionHeader
            eyebrow="Scan scope"
            title={coverageView === "languages" ? "Language coverage" : "Extension coverage"}
            description="Top five candidate file groups discovered before scanning."
            icon={<Code2 size={18} />}
            action={
              <div className="dashboard-segmented" role="group" aria-label="Coverage type">
                <button type="button" className={coverageView === "languages" ? "active" : ""} aria-pressed={coverageView === "languages"} onClick={() => setCoverageView("languages")}>Languages</button>
                <button type="button" className={coverageView === "extensions" ? "active" : ""} aria-pressed={coverageView === "extensions"} onClick={() => setCoverageView("extensions")}>Extensions</button>
              </div>
            }
          />
          <CoverageBars entries={coverageEntries} />
          <p className="dashboard-footnote">Coverage is a filesystem census; scanner-confirmed coverage is not yet reported.</p>
        </section>

        <section className="dashboard-card scanner-health-card">
          <DashboardSectionHeader eyebrow="Engine integrity" title="Scanner health" description="Execution and finding reconciliation for each engine." icon={<Database size={18} />} />
          <ScannerHealthDashboard report={snapshotReport} />
        </section>
      </div>

      <section className="dashboard-card priority-card">
        <DashboardSectionHeader
          eyebrow="Remediation queue"
          title="Priority findings"
          description="The five highest-severity findings from the latest assessment."
          icon={<AlertTriangle size={18} />}
          action={snapshotReport ? <button type="button" className="dashboard-text-action" onClick={() => onViewFindings(latestJob, snapshotReport)}>View all findings <ChevronRight size={16} /></button> : undefined}
        />
        <PriorityFindings findings={priorityFindings} reportAvailable={Boolean(snapshotReport)} onSelect={openFinding} />
      </section>

      <div className="dashboard-split dashboard-activity-grid">
        <section className="dashboard-card recent-card">
          <DashboardSectionHeader
            eyebrow="Activity"
            title="Recent scans"
            description="The six newest jobs currently available to this dashboard."
            icon={<Activity size={18} />}
            action={<button className="dashboard-text-action" onClick={onOpenReports}>View all reports <ChevronRight size={16} /></button>}
          />
          <RecentScans jobs={jobs.slice(0, 6)} onOpen={onOpenScan} />
        </section>

        <section className="dashboard-card attention-card">
          <DashboardSectionHeader eyebrow="Action center" title="Needs attention" description="The most important scan and integrity signals." icon={<CircleAlert size={18} />} />
          <AttentionList alerts={alerts} totalFindings={totalFindings} hasCompletedSnapshot={hasCompletedSnapshot} active={Boolean(activeJob)} />
        </section>
      </div>

      {selectedFinding && <FindingDrawer finding={selectedFinding} onClose={closeFinding} />}
    </section>
  );
}

function DashboardMetric({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: string | number; detail: string; tone: string }) {
  return (
    <article className={`dashboard-metric ${tone}`}>
      <div className="dashboard-metric-head"><span>{label}</span><div>{icon}</div></div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function DashboardSectionHeader({ eyebrow, title, description, icon, action }: { eyebrow: string; title: string; description: string; icon: ReactNode; action?: ReactNode }) {
  return (
    <header className="dashboard-section-head">
      <div className="dashboard-section-title">
        <div className="dashboard-section-icon">{icon}</div>
        <div><span>{eyebrow}</span><h2>{title}</h2><p>{description}</p></div>
      </div>
      {action && <div className="dashboard-section-action">{action}</div>}
    </header>
  );
}

function RiskTrend({ jobs, onOpenScan }: { jobs: ScanJob[]; onOpenScan: (job: ScanJob) => void }) {
  const points = jobs.filter((item) => finalStatuses.includes(item.status)).slice(0, 8).reverse();
  const maxTotal = Math.max(1, ...points.map((item) => summaryTotal(item.summary)));
  const chartSeverities = ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

  if (points.length === 0) return <DashboardMiniEmpty icon={<TrendingUp size={24} />} text="Complete a scan to start the risk trend." />;

  return (
    <>
      <div className="trend-legend" aria-label="Severity legend">
        {chartSeverities.slice().reverse().map((severity) => <span key={severity}><i style={{ background: severityColors[severity] }} />{titleCase(severity)}</span>)}
      </div>
      <div
        className="trend-chart"
        role="group"
        aria-label={`Stacked severity chart for ${points.length} recent scans`}
        style={{ gridTemplateColumns: `repeat(${points.length}, minmax(36px, 1fr))` }}
      >
        <div className="trend-grid-lines" aria-hidden="true"><span /><span /><span /></div>
        {points.map((item) => {
          const total = summaryTotal(item.summary);
          const title = `${item.target}\n${formatDateTime(item.created_at)}\n${severityOrder.map((severity) => `${titleCase(severity)}: ${summaryValue(item.summary, severity)}`).join(" • ")}`;
          return (
            <button type="button" className="trend-column" key={item.id} onClick={() => onOpenScan(item)} title={title} aria-label={`Open ${item.target}, ${total} findings. ${severityOrder.map((severity) => `${titleCase(severity)} ${summaryValue(item.summary, severity)}`).join(", ")}`}>
              <span className="trend-total">{total}</span>
              <span className="trend-stack">
                {chartSeverities.map((severity) => {
                  const value = summaryValue(item.summary, severity);
                  return <i key={severity} className={`trend-segment ${severity.toLowerCase()}`} style={{ height: `${(value / maxTotal) * 100}%` }} />;
                })}
              </span>
              <span className="trend-date">{formatShortDate(item.created_at)}</span>
            </button>
          );
        })}
      </div>
      <div className="trend-caption"><span>Oldest</span><span>Latest completed scans</span></div>
    </>
  );
}

function DistributionChart({ entries, mode }: { entries: Array<{ key: string; label: string; value: number; color: string }>; mode: "severity" | "category" }) {
  const visible = entries.filter((entry) => entry.value > 0);
  const total = visible.reduce((sum, entry) => sum + entry.value, 0);
  const gradient = donutGradient(visible, total);

  if (mode === "category") {
    if (!total) return <DashboardMiniEmpty icon={<BarChart3 size={24} />} text="No categorized findings in this report." />;
    return (
      <div className="category-bars">
        {visible.map((entry) => (
          <div className="category-bar-row" key={entry.key}>
            <div><span>{entry.label}</span><strong>{entry.value}</strong></div>
            <div className="category-track"><i style={{ width: `${total ? (entry.value / total) * 100 : 0}%`, background: entry.color }} /></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="donut-layout">
      <div className="donut-chart" role="img" aria-label={`${total} findings by severity`} style={{ background: gradient }}>
        <div><strong>{total}</strong><span>Total findings</span></div>
      </div>
      <div className="donut-legend">
        {entries.map((entry) => (
          <div key={entry.key}><span><i style={{ background: entry.color }} />{entry.label}</span><strong>{entry.value}<small>{total ? `${Math.round((entry.value / total) * 100)}%` : "0%"}</small></strong></div>
        ))}
      </div>
    </div>
  );
}

function CoverageBars({ entries }: { entries: Array<{ label: string; value: number; percentage: number }> }) {
  if (!entries.length) return <DashboardMiniEmpty icon={<Code2 size={24} />} text="No language or extension coverage is available." />;
  const colors = ["#2563eb", "#06b6d4", "#8b5cf6", "#14b8a6", "#f59e0b", "#94a3b8"];
  const total = entries.reduce((sum, entry) => sum + entry.value, 0);
  const gradient = donutGradient(entries.map((entry, index) => ({ value: entry.value, color: colors[index % colors.length] })), total);
  return (
    <div className="coverage-bars">
      <div className="coverage-ring" role="img" aria-label={`${total} candidate files across ${entries.length} reported groups`} style={{ background: gradient }}>
        <div><strong>{formatNumber(total)}</strong><span>Candidate files</span></div>
      </div>
      <div className="coverage-bar-list">
        {entries.map((entry, index) => (
          <div className="coverage-row" key={entry.label}>
            <div><strong><i style={{ background: colors[index % colors.length] }} />{entry.label}</strong><span>{entry.value} {entry.value === 1 ? "file" : "files"}</span></div>
            <div className="coverage-track"><i style={{ width: `${entry.percentage}%`, background: colors[index % colors.length] }} /></div>
            <em>{entry.percentage}%</em>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScannerHealthDashboard({ report }: { report: ScanReport | null }) {
  const reported = new Map((report?.scanners ?? []).map((scanner) => [scanner.scanner.trim().toLowerCase(), scanner]));
  const scanners = ["OpenGrep", "Trivy"].map((name) => ({ name, data: reported.get(name.toLowerCase()) }));
  const scannerRaw = scanners.reduce((sum, item) => sum + safeNumber(item.data?.raw_finding_count), 0);
  const scannerParsed = scanners.reduce((sum, item) => sum + safeNumber(item.data?.parsed_finding_count), 0);
  const scannerDropped = scanners.reduce((sum, item) => sum + safeNumber(item.data?.dropped_finding_count), 0);
  const raw = report?.integrity.scanner_raw_finding_count == null ? scannerRaw : safeNumber(report.integrity.scanner_raw_finding_count);
  const parsed = report?.integrity.scanner_parsed_finding_count == null ? scannerParsed : safeNumber(report.integrity.scanner_parsed_finding_count);
  const included = report?.integrity.final_report_finding_count == null ? report?.findings.length ?? 0 : safeNumber(report.integrity.final_report_finding_count);
  const dropped = report?.integrity.dropped_finding_count == null ? scannerDropped : safeNumber(report.integrity.dropped_finding_count);
  const reconciled = report?.integrity.all_parsed_findings_included;

  return (
    <div className="scanner-dashboard-list">
      {scanners.map(({ name, data }) => {
        const state = data?.status?.trim().toUpperCase() || "NOT REPORTED";
        const healthy = state === "SUCCESS";
        const active = state === "RUNNING" || state === "QUEUED";
        return (
          <article className="scanner-dashboard-row" key={name}>
            <div className={`scanner-state-icon ${statusClass(state)}`}>{healthy ? <CheckCircle2 size={18} /> : active ? <Loader2 className="spin" size={18} /> : <AlertTriangle size={18} />}</div>
            <div className="scanner-dashboard-name">
              <strong>{name}</strong>
              <span>{data?.version || "Version unavailable"}</span>
              {data && <small>{formatNumber(data.raw_finding_count)} raw · {formatNumber(data.parsed_finding_count)} parsed · {formatNumber(data.dropped_finding_count)} dropped</small>}
            </div>
            <div className="scanner-dashboard-result"><span className={`badge ${statusClass(state)}`}>{state}</span><small>{data ? formatDuration(data.duration_seconds) : "—"}</small></div>
          </article>
        );
      })}
      {report ? (
        <>
          <div className="integrity-flow" aria-label={`Raw ${raw}, parsed ${parsed}, included ${included}`}>
            <IntegrityStep label="Raw" value={raw} />
            <ChevronRight size={15} />
            <IntegrityStep label="Parsed" value={parsed} />
            <ChevronRight size={15} />
            <IntegrityStep label="Included" value={included} />
          </div>
          <div className="integrity-notes">
            <span className={dropped > 0 ? "warning" : ""}><strong>{dropped}</strong> dropped during parsing</span>
            <span className={reconciled === false ? "warning" : reconciled === true ? "success" : ""}>
              {reconciled === false ? <AlertTriangle size={14} /> : <ShieldCheck size={14} />}
              {reconciled === false ? "Report mismatch" : reconciled === true ? "Fully reconciled" : "Verdict unavailable"}
            </span>
          </div>
        </>
      ) : (
        <div className="integrity-verdict neutral"><CircleAlert size={14} />Detailed scanner integrity is unavailable.</div>
      )}
    </div>
  );
}

function IntegrityStep({ label, value, alert = false }: { label: string; value: number; alert?: boolean }) {
  return <div className={alert ? "alert" : ""}><span>{label}</span><strong>{value}</strong></div>;
}

function PriorityFindings({ findings, reportAvailable, onSelect }: { findings: Finding[]; reportAvailable: boolean; onSelect: (finding: Finding, trigger: HTMLButtonElement) => void }) {
  if (!findings.length) {
    return <DashboardMiniEmpty icon={reportAvailable ? <ShieldCheck size={26} /> : <CircleAlert size={26} />} text={reportAvailable ? "No findings were included in the latest report." : "Detailed findings are unavailable for this scan."} positive={reportAvailable} />;
  }
  return (
    <>
      <div className="priority-table-wrap" tabIndex={0} aria-label="Priority findings table; scroll horizontally if needed">
        <table className="priority-table">
          <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Location</th><th>Scanner</th><th><span className="sr-only">Action</span></th></tr></thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.finding_id}>
                <td><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span></td>
                <td><button type="button" className="finding-title-button" onClick={(event) => onSelect(finding, event.currentTarget)}><strong>{finding.title}</strong><span>{finding.rule_id ?? finding.cve ?? "Scanner finding"}</span></button></td>
                <td><span className="category-chip">{friendlyCategory(finding.category)}</span></td>
                <td><span className="finding-location" title={finding.file ?? undefined}>{finding.file ?? "—"}{finding.line_start ? `:${finding.line_start}` : ""}</span></td>
                <td>{finding.scanner}</td>
                <td><button type="button" className="row-action" onClick={(event) => onSelect(finding, event.currentTarget)} aria-label={`View details for ${finding.title}`}><ChevronRight size={17} /></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="priority-mobile-list">
        {findings.map((finding) => (
          <button type="button" className="priority-mobile-card" key={finding.finding_id} onClick={(event) => onSelect(finding, event.currentTarget)}>
            <span><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><span className="category-chip">{friendlyCategory(finding.category)}</span></span>
            <strong>{finding.title}</strong>
            <small>{finding.rule_id ?? finding.cve ?? finding.scanner}</small>
            <em>{finding.file ?? "Location unavailable"}{finding.line_start ? `:${finding.line_start}` : ""}</em>
          </button>
        ))}
      </div>
    </>
  );
}

function RecentScans({ jobs, onOpen }: { jobs: ScanJob[]; onOpen: (job: ScanJob) => void }) {
  if (!jobs.length) return <DashboardMiniEmpty icon={<Activity size={24} />} text="No recent scan activity is available." />;
  return (
    <div className="recent-scan-list">
      {jobs.map((item) => (
        <article className="recent-scan-row" key={item.id}>
          <div className={`recent-source-icon ${item.target_type}`}>{sourceIcon(item.target_type)}</div>
          <div className="recent-target"><strong title={item.target}>{item.target}</strong><span>{sourceLabel(item.target_type)} • {formatDateTime(item.created_at)}</span></div>
          <div className="recent-risk"><strong>{summaryValue(item.summary, "CRITICAL") + summaryValue(item.summary, "HIGH")}</strong><span>Critical + high</span></div>
          <div className="recent-findings"><strong>{summaryTotal(item.summary)}</strong><span>Findings</span></div>
          <span className={`badge ${statusClass(item.status)}`}>{item.status}</span>
          <button type="button" className="row-action" onClick={() => onOpen(item)} aria-label={`Open scan for ${item.target}`}><ChevronRight size={17} /></button>
        </article>
      ))}
    </div>
  );
}

function AttentionList({ alerts, totalFindings, hasCompletedSnapshot, active }: { alerts: DashboardAlert[]; totalFindings: number; hasCompletedSnapshot: boolean; active: boolean }) {
  if (!alerts.length) {
    return (
      <div className="attention-healthy">
        <div><ShieldCheck size={26} /></div>
        <strong>No operational alerts</strong>
        <p>{!hasCompletedSnapshot && active ? "The first assessment is still running; results will appear when it finishes." : totalFindings ? "Scanner execution and report integrity are healthy; review the remediation queue next." : "The latest completed assessment has no included findings."}</p>
      </div>
    );
  }
  return (
    <div className="attention-list">
      {alerts.slice(0, 3).map((alert) => (
        <article className={`attention-item ${alert.tone}`} key={`${alert.title}-${alert.detail}`}>
          <div>{alert.tone === "critical" ? <AlertTriangle size={18} /> : <CircleAlert size={18} />}</div>
          <span><strong>{alert.title}</strong><small>{alert.detail}</small></span>
        </article>
      ))}
    </div>
  );
}

function DashboardMiniEmpty({ icon, text, positive = false }: { icon: ReactNode; text: string; positive?: boolean }) {
  return <div className={`dashboard-mini-empty ${positive ? "positive" : ""}`}><div>{icon}</div><span>{text}</span></div>;
}

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  function trapFocus(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Tab") return;
    const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button, a[href], [tabindex]:not([tabindex="-1"])'));
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="finding-drawer-backdrop" onMouseDown={onClose}>
      <aside className="finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title" onKeyDown={trapFocus} onMouseDown={(event) => event.stopPropagation()}>
        <header>
          <div><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><span className="category-chip">{friendlyCategory(finding.category)}</span></div>
          <button type="button" autoFocus onClick={onClose} aria-label="Close finding details"><X size={20} /></button>
        </header>
        <div className="finding-drawer-body">
          <span className="eyebrow">{finding.scanner} finding</span>
          <h2 id="finding-drawer-title">{finding.title}</h2>
          <p className="finding-drawer-description">{finding.description || "No scanner description was provided."}</p>
          <dl className="finding-detail-grid">
            <dt>Rule / CVE</dt><dd>{finding.rule_id ?? finding.cve ?? "—"}</dd>
            <dt>Location</dt><dd>{finding.file ?? "—"}{finding.line_start ? `:${finding.line_start}` : ""}</dd>
            <dt>CWE</dt><dd>{finding.cwe?.join(", ") || "—"}</dd>
            <dt>OWASP</dt><dd>{finding.owasp?.join(", ") || "—"}</dd>
            <dt>Confidence</dt><dd>{finding.confidence ?? "—"}</dd>
            <dt>CVSS</dt><dd>{finding.cvss ?? "—"}</dd>
            {finding.package && <><dt>Package</dt><dd>{finding.package} {finding.installed_version ? `(${finding.installed_version})` : ""}</dd></>}
            {finding.fixed_version && <><dt>Fixed version</dt><dd>{finding.fixed_version}</dd></>}
          </dl>
          {finding.code_snippet && <section className="finding-evidence"><h3>Evidence</h3><pre>{finding.code_snippet}</pre></section>}
          <section className="finding-remediation"><h3>Recommended remediation</h3><p>{finding.remediation || "Review the scanner guidance, validate exploitability, and apply a secure fix."}</p></section>
          {Boolean(finding.references?.length) && <section className="finding-references"><h3>References</h3>{finding.references?.slice(0, 5).map((reference) => <a key={reference} href={reference} target="_blank" rel="noreferrer">{reference}<ExternalLink size={14} /></a>)}</section>}
        </div>
      </aside>
    </div>
  );
}

interface DashboardAlert { tone: "critical" | "warning" | "info"; title: string; detail: string }

function reportMatchesJob(report: ScanReport, job: ScanJob): boolean {
  if (!finalStatuses.includes(report.status)) return false;
  if (job.status !== "ERROR" && report.status !== job.status) return false;
  const reportTimestamp = safeDate(report.metadata.started_at);
  const jobStarted = safeDate(job.started_at ?? job.created_at);
  const jobFinished = safeDate(job.finished_at);
  if (!reportTimestamp || !jobStarted || !jobFinished) return false;
  return reportTimestamp >= jobStarted && reportTimestamp <= jobFinished + 1000;
}

function safeNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function summaryValue(summary: Record<string, number> | undefined, severity: string): number {
  return safeNumber(summary?.[severity]);
}

function summaryTotal(summary: Record<string, number> | undefined): number {
  if (summary && Number.isFinite(Number(summary.TOTAL))) return safeNumber(summary.TOTAL);
  return severityOrder.reduce((total, severity) => total + summaryValue(summary, severity), 0);
}

function severityRank(severity: string): number {
  return { UNKNOWN: 0, INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 }[severity.toUpperCase()] ?? 0;
}

function safeDate(value: string | null | undefined): number {
  if (!value) return 0;
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function jobDuration(job: ScanJob | null): number | null {
  if (!job?.started_at || !job.finished_at) return null;
  return Math.max(0, (safeDate(job.finished_at) - safeDate(job.started_at)) / 1000);
}

function jobArtifactTime(job: ScanJob): number {
  return safeDate(job.finished_at ?? job.started_at ?? job.created_at);
}

function getNewestTerminalJob(jobs: ScanJob[]): ScanJob | null {
  return jobs.reduce<ScanJob | null>((latest, item) => {
    if (!finalStatuses.includes(item.status)) return latest;
    return !latest || jobArtifactTime(item) > jobArtifactTime(latest) ? item : latest;
  }, null);
}

function reportArtifactMarker(job: ScanJob | null): string {
  return job ? `${job.id}:${job.status}:${job.finished_at ?? job.started_at ?? job.created_at}` : "";
}

function formatDuration(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "—";
  const seconds = Math.max(0, Number(value));
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "—";
  return Math.max(0, Number(value)).toLocaleString();
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Date unavailable";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatShortDate(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function titleCase(value: string): string {
  return value.toLowerCase().replace(/(^|[\s_-])\w/g, (letter) => letter.toUpperCase());
}

function friendlyCategory(value: string): string {
  const normalized = value.trim().toUpperCase();
  return { SAST: "SAST", SCA: "Dependencies", SECRETS: "Secrets", MISCONFIGURATION: "Misconfiguration" }[normalized] ?? titleCase(value || "Uncategorized");
}

function sourceLabel(type: TargetType): string {
  return { github: "GitHub repository", file: "File upload", folder: "Folder upload", zip: "ZIP archive", local_path: "Local workspace" }[type];
}

function sourceIcon(type: TargetType): ReactNode {
  if (type === "github") return <Link size={18} />;
  if (type === "folder") return <Folder size={18} />;
  if (type === "zip") return <Archive size={18} />;
  if (type === "local_path") return <TerminalSquare size={18} />;
  return <FileCode2 size={18} />;
}

function statusExplanation(status: string, threshold?: string): string {
  const normalized = status.toUpperCase();
  if (normalized === "FAILED") return `Policy threshold ${threshold ?? "HIGH"}+ reached`;
  if (normalized === "SUCCESS") return "Security policy passed";
  if (normalized === "PARTIAL") return "One or more scanners were incomplete";
  if (normalized === "ERROR") return "Scan execution needs attention";
  if (normalized === "RUNNING") return "Assessment is in progress";
  if (normalized === "QUEUED") return "Waiting for scanner capacity";
  return "Ready for an assessment";
}

function buildCategoryEntries(findings: Finding[]): Array<{ key: string; label: string; value: number; color: string }> {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const category = finding.category?.trim().toUpperCase() || "UNCATEGORIZED";
    counts.set(category, (counts.get(category) ?? 0) + 1);
  }
  const palette: Record<string, string> = { SAST: "#2563eb", SCA: "#8b5cf6", SECRETS: "#ef4444", MISCONFIGURATION: "#f59e0b", UNCATEGORIZED: "#94a3b8" };
  const sorted = Array.from(counts.entries()).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  const top = sorted.slice(0, 5);
  const other = sorted.slice(5).reduce((sum, [, value]) => sum + value, 0);
  if (other) top.push(["OTHER", other]);
  return top.map(([key, value], index) => ({
    key,
    label: key === "OTHER" ? "Other" : friendlyCategory(key),
    value,
    color: palette[key] ?? ["#06b6d4", "#14b8a6", "#6366f1", "#64748b"][index % 4]
  }));
}

function buildCoverageEntries(source: Record<string, number> | undefined): Array<{ label: string; value: number; percentage: number }> {
  const all = Object.entries(source ?? {})
    .map(([label, value]) => ({ label, value: safeNumber(value) }))
    .filter((entry) => entry.value > 0)
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
  const total = all.reduce((sum, entry) => sum + entry.value, 0);
  const top = all.slice(0, 5);
  const other = all.slice(5).reduce((sum, entry) => sum + entry.value, 0);
  if (other) top.push({ label: "Other", value: other });
  return top.map((entry) => ({ ...entry, percentage: total ? Number(((entry.value / total) * 100).toFixed(1)) : 0 }));
}

function donutGradient(entries: Array<{ value: number; color: string }>, total: number): string {
  if (!total) return "conic-gradient(#e8eef8 0 100%)";
  let cursor = 0;
  const stops = entries.map((entry) => {
    const start = cursor;
    cursor += (entry.value / total) * 100;
    return `${entry.color} ${start}% ${cursor}%`;
  });
  return `conic-gradient(${stops.join(", ")})`;
}

function buildDashboardAlerts(report: ScanReport | null, latestJob: ScanJob | null, dashboardError: string): DashboardAlert[] {
  const alerts: DashboardAlert[] = [];
  if (dashboardError) alerts.push({ tone: "warning", title: "Dashboard refresh incomplete", detail: dashboardError });

  const status = report?.status ?? latestJob?.status;
  if (status === "ERROR") alerts.push({ tone: "critical", title: "Latest scan failed", detail: latestJob?.error || "The scanner could not produce a complete assessment." });
  else if (status === "FAILED" || report?.policy_failed) {
    const threshold = report?.policy_fail_on?.toUpperCase() || "HIGH";
    const thresholdCount = severityOrder
      .filter((severity) => severityRank(severity) >= severityRank(threshold))
      .reduce((total, severity) => total + summaryValue(report?.summary ?? latestJob?.summary, severity), 0);
    alerts.push({ tone: "critical", title: "Security policy failed", detail: `${thresholdCount} ${threshold}+ ${thresholdCount === 1 ? "finding meets" : "findings meet"} the policy threshold.` });
  } else if (status === "PARTIAL") {
    alerts.push({ tone: "warning", title: "Scan completed partially", detail: "One or more scanner engines did not finish successfully." });
  }

  const scannerProblems = (report?.scanners ?? []).filter((scanner) => scanner.status.trim().toUpperCase() !== "SUCCESS");
  if (scannerProblems.length) alerts.push({ tone: "warning", title: "Scanner execution incomplete", detail: scannerProblems.map((scanner) => `${scanner.scanner}: ${scanner.status}`).join(" • ") });

  const dropped = safeNumber(report?.integrity.dropped_finding_count ?? latestJob?.integrity.dropped_finding_count);
  if (dropped) alerts.push({ tone: "warning", title: "Findings were dropped", detail: `${dropped} raw scanner ${dropped === 1 ? "finding was" : "findings were"} not included after parsing.` });
  else if (report?.integrity.all_parsed_findings_included === false) alerts.push({ tone: "warning", title: "Report integrity mismatch", detail: "The parsed finding count does not match the final report count." });

  const diagnosticCount = (report?.errors?.length ?? 0) + (report?.warnings?.length ?? 0);
  if (diagnosticCount) alerts.push({ tone: "warning", title: "Scanner diagnostics reported", detail: `${diagnosticCount} scanner ${diagnosticCount === 1 ? "message needs" : "messages need"} review in the full report.` });

  const urgent = summaryValue(report?.summary ?? latestJob?.summary, "CRITICAL") + summaryValue(report?.summary ?? latestJob?.summary, "HIGH");
  if (!alerts.length && urgent > 0) alerts.push({ tone: "info", title: "Priority findings are open", detail: `${urgent} critical or high ${urgent === 1 ? "finding is" : "findings are"} ready for remediation.` });
  return alerts;
}

function ReportsPage({
  history,
  historyLoaded,
  historyError,
  historyUpdatedAt,
  currentJob,
  onRefresh,
  onNewScan,
  onReviewFindings
}: {
  history: ScanJob[];
  historyLoaded: boolean;
  historyError: string;
  historyUpdatedAt: Date | null;
  currentJob: ScanJob | null;
  onRefresh: () => Promise<boolean>;
  onNewScan: () => void;
  onReviewFindings: (job: ScanJob, report: ScanReport) => void;
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<ScanJob["status"] | "ALL">("ALL");
  const [sourceFilter, setSourceFilter] = useState<TargetType | "ALL">("ALL");
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest" | "findings">("newest");
  const [page, setPage] = useState(1);
  const [refreshing, setRefreshing] = useState(false);
  const [liveHistoryJobs, setLiveHistoryJobs] = useState<Record<string, ScanJob>>({});
  const [activityPollError, setActivityPollError] = useState("");
  const [detailJob, setDetailJob] = useState<ScanJob | null>(null);
  const [detailReport, setDetailReport] = useState<ScanReport | null>(null);
  const [detailError, setDetailError] = useState("");
  const [detailOpening, setDetailOpening] = useState(false);
  const [detailVerificationMarker, setDetailVerificationMarker] = useState("");
  const [exportOpening, setExportOpening] = useState<keyof ScanJob["reports"] | null>(null);
  const [exportError, setExportError] = useState("");
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);
  const reportsHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const detailRequestRef = useRef(0);
  const exportRequestRef = useRef(0);
  const refreshGuardRef = useRef(false);
  const onRefreshRef = useRef(onRefresh);
  const pageSize = 8;

  const jobs = useMemo(() => {
    const byId = new Map(history.map((item) => [item.id, item]));
    Object.values(liveHistoryJobs).forEach((item) => byId.set(item.id, item));
    if (currentJob) byId.set(currentJob.id, currentJob);
    return Array.from(byId.values()).sort((left, right) => safeDate(right.created_at) - safeDate(left.created_at));
  }, [history, liveHistoryJobs, currentJob]);

  const filteredJobs = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase();
    return jobs
      .filter((item) => !normalizedQuery || [item.target, item.id, item.target_type, item.status].some((value) => value.toLowerCase().includes(normalizedQuery)))
      .filter((item) => statusFilter === "ALL" || item.status === statusFilter)
      .filter((item) => sourceFilter === "ALL" || item.target_type === sourceFilter)
      .sort((left, right) => {
        if (sortOrder === "oldest") return safeDate(left.created_at) - safeDate(right.created_at);
        if (sortOrder === "findings") return summaryTotal(right.summary) - summaryTotal(left.summary) || safeDate(right.created_at) - safeDate(left.created_at);
        return safeDate(right.created_at) - safeDate(left.created_at);
      });
  }, [jobs, searchQuery, statusFilter, sourceFilter, sortOrder]);

  const totalPages = Math.max(1, Math.ceil(filteredJobs.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const visibleJobs = filteredJobs.slice(start, start + pageSize);
  const activeJob = jobs.find((item) => item.status === "QUEUED" || item.status === "RUNNING") ?? null;
  const completedCount = jobs.filter((item) => finalStatuses.includes(item.status)).length;
  const failedCount = jobs.filter((item) => item.status === "FAILED").length;
  const attentionCount = jobs.filter((item) => item.status === "PARTIAL" || item.status === "ERROR").length;
  const activeDetailJob = detailJob ? jobs.find((item) => item.id === detailJob.id) ?? detailJob : null;
  const latestTerminalJob = getNewestTerminalJob(jobs);
  const latestTerminalMarker = reportArtifactMarker(latestTerminalJob);
  const matchedDetailReport = activeDetailJob && detailReport && reportMatchesJob(detailReport, activeDetailJob) ? detailReport : null;
  const artifactNeedsRevalidation = Boolean(
    matchedDetailReport
      && activeDetailJob
      && latestTerminalJob
      && latestTerminalJob.id !== activeDetailJob.id
      && jobArtifactTime(latestTerminalJob) > jobArtifactTime(activeDetailJob)
      && detailVerificationMarker !== latestTerminalMarker
  );
  const coherentDetailReport = matchedDetailReport;
  const detailTransitioning = Boolean(
    detailJob
      && activeDetailJob
      && (detailJob.status === "QUEUED" || detailJob.status === "RUNNING")
      && finalStatuses.includes(activeDetailJob.status)
      && !coherentDetailReport
      && !detailError
  );
  const externalActiveJobIds = jobs
    .filter((item) => (item.status === "QUEUED" || item.status === "RUNNING") && item.id !== currentJob?.id)
    .map((item) => item.id)
    .sort();
  const externalActiveJobKey = externalActiveJobIds.join("|");
  const otherActiveJob = activeDetailJob
    ? jobs.find((item) => (item.status === "QUEUED" || item.status === "RUNNING") && item.id !== activeDetailJob.id) ?? null
    : null;
  const exportBlocked = Boolean(matchedDetailReport && (otherActiveJob || artifactNeedsRevalidation));
  const reviewBlocked = Boolean(otherActiveJob);
  const filtersActive = Boolean(searchQuery || statusFilter !== "ALL" || sourceFilter !== "ALL" || sortOrder !== "newest");

  useEffect(() => setPage(1), [searchQuery, statusFilter, sourceFilter, sortOrder, jobs.length]);

  useEffect(() => {
    onRefreshRef.current = onRefresh;
  }, [onRefresh]);

  useEffect(() => {
    let cancelled = false;
    let timer = 0;

    const discoverHistory = async () => {
      if (!refreshGuardRef.current) await onRefreshRef.current();
      if (!cancelled) timer = window.setTimeout(discoverHistory, 6000);
    };

    timer = window.setTimeout(discoverHistory, 6000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    if (!externalActiveJobKey) {
      setActivityPollError("");
      return;
    }

    const jobIds = externalActiveJobKey.split("|");
    let cancelled = false;
    let timer = 0;

    const pollActiveHistory = async () => {
      const results = await Promise.allSettled(jobIds.map((jobId) => getScan(jobId)));
      if (cancelled) return;

      const updates: ScanJob[] = [];
      let failedUpdates = 0;
      results.forEach((result) => {
        if (result.status === "fulfilled") updates.push(result.value);
        else failedUpdates += 1;
      });

      if (updates.length) {
        setLiveHistoryJobs((existing) => {
          const next = { ...existing };
          updates.forEach((item) => { next[item.id] = item; });
          return next;
        });
        if (updates.some((item) => finalStatuses.includes(item.status))) void onRefreshRef.current();
      }
      setActivityPollError(failedUpdates ? "Some active job updates are delayed. Refresh to retry the connection." : "");
      if (!cancelled) timer = window.setTimeout(pollActiveHistory, 2500);
    };

    timer = window.setTimeout(pollActiveHistory, 800);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [externalActiveJobKey]);

  useEffect(() => {
    if (!detailJob || !activeDetailJob || detailJob.id !== activeDetailJob.id) return;
    const wasActive = detailJob.status === "QUEUED" || detailJob.status === "RUNNING";
    if (wasActive && finalStatuses.includes(activeDetailJob.status)) void loadDetailReport(activeDetailJob);
  }, [detailJob?.id, detailJob?.status, activeDetailJob?.id, activeDetailJob?.status]);

  useEffect(() => {
    if (!artifactNeedsRevalidation || !activeDetailJob) return;
    void loadDetailReport(activeDetailJob);
  }, [artifactNeedsRevalidation, activeDetailJob?.id, latestTerminalMarker]);

  useEffect(() => {
    if (!detailJob) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeDetails();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [detailJob]);

  async function refreshReports() {
    if (refreshGuardRef.current) return;
    refreshGuardRef.current = true;
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      refreshGuardRef.current = false;
      setRefreshing(false);
    }
  }

  async function loadDetailReport(item: ScanJob) {
    if (!finalStatuses.includes(item.status)) return;
    const requestId = ++detailRequestRef.current;
    const verificationMarker = latestTerminalMarker;
    exportRequestRef.current += 1;
    setDetailReport(null);
    setDetailError("");
    setDetailOpening(true);
    setExportOpening(null);
    setExportError("");
    try {
      const nextReport = await getReport(item);
      if (requestId !== detailRequestRef.current) return;
      if (!reportMatchesJob(nextReport, item)) throw new Error("This job's historical artifact has been replaced by a different scan report.");
      setDetailReport(nextReport);
      setDetailVerificationMarker(verificationMarker);
    } catch (loadError) {
      if (requestId !== detailRequestRef.current) return;
      setDetailVerificationMarker("");
      setDetailError(loadError instanceof Error ? loadError.message : "The verified report could not be loaded.");
    } finally {
      if (requestId === detailRequestRef.current) setDetailOpening(false);
    }
  }

  function openDetails(item: ScanJob, trigger: HTMLButtonElement) {
    detailRequestRef.current += 1;
    exportRequestRef.current += 1;
    detailTriggerRef.current = trigger;
    setDetailJob(item);
    setDetailReport(null);
    setDetailError("");
    setDetailOpening(false);
    setDetailVerificationMarker("");
    setExportOpening(null);
    setExportError("");
    if (finalStatuses.includes(item.status)) void loadDetailReport(item);
  }

  function retryDetails() {
    if (!activeDetailJob) return;
    void loadDetailReport(activeDetailJob);
  }

  function closeDetails() {
    detailRequestRef.current += 1;
    exportRequestRef.current += 1;
    setDetailOpening(false);
    setDetailReport(null);
    setDetailError("");
    setDetailVerificationMarker("");
    setExportOpening(null);
    setExportError("");
    setDetailJob(null);
    window.setTimeout(() => {
      if (detailTriggerRef.current?.isConnected) detailTriggerRef.current.focus();
      else reportsHeadingRef.current?.focus();
    }, 0);
  }

  function rememberHistorySnapshot(snapshot: ScanJob[]) {
    setLiveHistoryJobs((existing) => {
      const next = { ...existing };
      snapshot.forEach((item) => { next[item.id] = item; });
      return next;
    });
  }

  async function openVerifiedExport(format: keyof ScanJob["reports"]) {
    if (!activeDetailJob || !coherentDetailReport || exportBlocked || exportOpening) return;
    const selectedJob = activeDetailJob;
    if (selectedJob.error && format !== "json") {
      setExportError("Only the verified JSON report is available because this job failed before every export could be proven complete.");
      return;
    }
    const requestId = ++exportRequestRef.current;
    const verificationWindow = window.open("about:blank", "_blank");
    if (verificationWindow) {
      verificationWindow.opener = null;
      verificationWindow.document.title = "Verifying report";
      verificationWindow.document.body.textContent = "Verifying report ownership before opening the file…";
    }
    setExportOpening(format);
    setExportError("");
    let invalidateReport = false;

    try {
      const firstSnapshot = await listScans();
      if (requestId !== exportRequestRef.current) {
        verificationWindow?.close();
        return;
      }
      rememberHistorySnapshot(firstSnapshot);
      if (firstSnapshot.some((item) => item.id !== selectedJob.id && (item.status === "QUEUED" || item.status === "RUNNING"))) {
        throw new Error("Export is paused because another scan is active. Try again after it finishes.");
      }

      const firstArtifact = await getReport(selectedJob);
      if (requestId !== exportRequestRef.current) {
        verificationWindow?.close();
        return;
      }
      if (!reportMatchesJob(firstArtifact, selectedJob)) {
        invalidateReport = true;
        throw new Error("The shared report files now belong to a different scan.");
      }

      const artifactResponse = await fetch(resolveApiUrl(selectedJob.reports[format]), { cache: "no-store" });
      if (requestId !== exportRequestRef.current) {
        verificationWindow?.close();
        return;
      }
      if (!artifactResponse.ok) throw new Error(`${format.toUpperCase()} export could not be fetched (${artifactResponse.status}).`);
      const capturedArtifact = await artifactResponse.blob();
      if (!capturedArtifact.size) throw new Error(`${format.toUpperCase()} export is empty.`);

      const finalArtifact = await getReport(selectedJob);
      if (requestId !== exportRequestRef.current) {
        verificationWindow?.close();
        return;
      }
      if (!reportMatchesJob(finalArtifact, selectedJob)) {
        invalidateReport = true;
        throw new Error("The shared report files changed during verification and no longer belong to this scan.");
      }

      const finalSnapshot = await listScans();
      if (requestId !== exportRequestRef.current) {
        verificationWindow?.close();
        return;
      }
      rememberHistorySnapshot(finalSnapshot);
      if (finalSnapshot.some((item) => item.id !== selectedJob.id && (item.status === "QUEUED" || item.status === "RUNNING"))) {
        throw new Error("Export is paused because another scan is active. Try again after it finishes.");
      }

      setDetailReport(finalArtifact);
      setDetailVerificationMarker(reportArtifactMarker(getNewestTerminalJob(finalSnapshot)));
      const objectUrl = URL.createObjectURL(capturedArtifact);
      if (format === "pdf") {
        verificationWindow?.close();
        const downloadLink = document.createElement("a");
        downloadLink.href = objectUrl;
        downloadLink.download = `scan-${selectedJob.id.slice(0, 8)}.pdf`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        downloadLink.remove();
      } else if (verificationWindow && !verificationWindow.closed) {
        verificationWindow.location.replace(objectUrl);
      } else {
        window.open(objectUrl, "_blank", "noopener,noreferrer");
      }
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
    } catch (exportFailure) {
      verificationWindow?.close();
      if (requestId !== exportRequestRef.current) return;
      const message = exportFailure instanceof Error ? exportFailure.message : "The report could not be verified for export.";
      if (invalidateReport) {
        setDetailReport(null);
        setDetailVerificationMarker("");
        setDetailError(message);
      } else {
        setExportError(`${message} No file was opened.`);
      }
    } finally {
      if (requestId === exportRequestRef.current) setExportOpening(null);
    }
  }

  function clearFilters() {
    setSearchQuery("");
    setStatusFilter("ALL");
    setSourceFilter("ALL");
    setSortOrder("newest");
  }

  return (
    <section className="reports-page">
      <section className="reports-header-card">
        <div className="reports-header-copy">
          <span className="reports-kicker"><FileJson size={15} /> Security evidence</span>
          <h2 ref={reportsHeadingRef} tabIndex={-1}>Reports and scan history</h2>
          <p>Review recent assessment outcomes, inspect scanner integrity, and open verified report artifacts.</p>
          <div className="reports-context-notes"><span className="reports-scope-note"><CircleAlert size={14} />The API currently exposes the 25 most recent jobs.</span>{historyUpdatedAt && <span><Clock3 size={14} />Updated {historyUpdatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>}</div>
        </div>
        <div className="reports-header-actions">
          <button type="button" className="reports-refresh-button" onClick={() => void refreshReports()} disabled={refreshing}>
            <RefreshCcw className={refreshing ? "spin" : ""} size={17} /> {refreshing ? "Refreshing…" : "Refresh"}
          </button>
          <button type="button" className="reports-new-button" onClick={onNewScan}><Play size={17} /> New Scan</button>
        </div>
      </section>

      {historyError && <div className="reports-inline-error" role="alert"><AlertTriangle size={17} /><span>{historyError}</span><button type="button" onClick={() => void refreshReports()} disabled={refreshing}>Try again</button></div>}
      {activityPollError && <div className="reports-inline-error reports-poll-warning" role="status"><CircleAlert size={17} /><span>{activityPollError}</span><button type="button" onClick={() => void refreshReports()} disabled={refreshing}>Refresh</button></div>}

      {activeJob && (
        <section className="reports-active-banner" aria-live="polite">
          <div><Loader2 className="spin" size={18} /></div>
          <span><strong>{activeJob.status === "QUEUED" ? "A scan is waiting to start" : "A security assessment is running"}</strong><small title={activeJob.target}>{activeJob.target} · {activeJob.progress_message || statusExplanation(activeJob.status)}</small></span>
          <span className={`badge ${statusClass(activeJob.status)}`}>{activeJob.status}</span>
        </section>
      )}

      {!historyLoaded ? (
        <ReportsLoadingState />
      ) : (
        <>
          <div className="reports-metrics">
            <ReportsMetric icon={<Files size={18} />} label="Recent jobs" value={jobs.length} detail="Loaded history snapshot" tone="blue" />
            <ReportsMetric icon={<ShieldCheck size={18} />} label="Finished" value={completedCount} detail="All terminal outcomes" tone="green" />
            <ReportsMetric icon={<AlertTriangle size={18} />} label="FAILED jobs" value={failedCount} detail="Policy threshold reached" tone="red" />
            <ReportsMetric icon={<CircleAlert size={18} />} label="Needs attention" value={attentionCount} detail="Partial or execution error" tone="amber" />
          </div>

          <section className="reports-history-card">
            <header className="reports-history-head">
              <div><span>Recent activity</span><h3>Scan history</h3><p>Search and filter the jobs currently retained by the API.</p></div>
              <strong>{filteredJobs.length} {filteredJobs.length === 1 ? "result" : "results"}</strong>
            </header>

            <div className="reports-toolbar">
              <label className="reports-search"><Search size={17} /><span className="sr-only">Search scan history</span><input value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Search target, source, status, or job ID…" /></label>
              <label><span className="sr-only">Filter by status</span><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as ScanJob["status"] | "ALL")}><option value="ALL">All statuses</option>{["QUEUED", "RUNNING", ...finalStatuses].map((status) => <option value={status} key={status}>{titleCase(status)}</option>)}</select></label>
              <label><span className="sr-only">Filter by source</span><select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value as TargetType | "ALL")}><option value="ALL">All sources</option><option value="github">GitHub</option><option value="file">File upload</option><option value="folder">Folder upload</option><option value="zip">ZIP archive</option><option value="local_path">Scanner workspace</option></select></label>
              <label><span className="sr-only">Sort reports</span><select value={sortOrder} onChange={(event) => setSortOrder(event.target.value as "newest" | "oldest" | "findings")}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="findings">Most findings</option></select></label>
              {filtersActive && <button type="button" className="reports-clear-button" onClick={clearFilters}><RotateCcw size={15} /> Clear</button>}
            </div>

            {jobs.length === 0 ? (
              <ReportsEmptyState icon={<FileJson size={28} />} title="No scan reports yet" detail="Start your first assessment to create a report and populate this history." action={<button type="button" onClick={onNewScan}><Play size={16} /> Start a new scan</button>} />
            ) : filteredJobs.length === 0 ? (
              <ReportsEmptyState icon={<Search size={26} />} title="No reports match these filters" detail="Change the search or filters to return to the available scan history." action={<button type="button" onClick={clearFilters}><RotateCcw size={16} /> Clear filters</button>} />
            ) : (
              <>
                <div className="reports-table-wrap" tabIndex={0} aria-label="Scan history table; scroll horizontally if needed">
                  <table className="reports-table">
                    <thead><tr><th>Status</th><th>Target</th><th>Created</th><th>Duration</th><th>Critical + High</th><th>Findings</th><th>Files</th><th><span className="sr-only">Action</span></th></tr></thead>
                    <tbody>{visibleJobs.map((item) => {
                      const priority = summaryValue(item.summary, "CRITICAL") + summaryValue(item.summary, "HIGH");
                      const active = item.status === "QUEUED" || item.status === "RUNNING";
                      const outcomeUnavailable = item.status === "ERROR" && Object.keys(item.summary ?? {}).length === 0;
                      return (
                        <tr key={item.id} className={detailJob?.id === item.id ? "selected" : ""}>
                          <td><span className={`badge ${statusClass(item.status)}`}>{item.status}</span></td>
                          <td><div className={`reports-source-icon ${item.target_type}`}>{sourceIcon(item.target_type)}</div><span className="reports-target"><strong title={item.target}>{item.target}</strong><small>{sourceLabel(item.target_type)} · {item.id.slice(0, 8)}</small></span></td>
                          <td><span className="reports-date"><strong>{formatDateTime(item.created_at)}</strong><small>{item.finished_at ? "Finished" : active ? "Active" : "Not finished"}</small></span></td>
                          <td>{active && item.started_at ? formatLiveDuration(item.started_at) : formatDuration(jobDuration(item))}</td>
                          <td>{active ? <span className="reports-pending">Pending</span> : outcomeUnavailable ? <span className="reports-pending">Unavailable</span> : <span className={`reports-priority ${priority ? "has-risk" : ""}`}>{priority}</span>}</td>
                          <td>{active || outcomeUnavailable ? <span className="reports-pending">—</span> : <strong className="reports-count">{summaryTotal(item.summary)}</strong>}</td>
                          <td>{active || outcomeUnavailable ? <span className="reports-pending">—</span> : formatNumber(item.coverage?.files_scanned)}</td>
                          <td><button type="button" className="reports-row-action" onClick={(event) => void openDetails(item, event.currentTarget)} aria-label={`Open report details for ${item.target}`}><span>View report</span><ChevronRight size={17} /></button></td>
                        </tr>
                      );
                    })}</tbody>
                  </table>
                </div>

                <div className="reports-mobile-list">{visibleJobs.map((item) => {
                  const priority = summaryValue(item.summary, "CRITICAL") + summaryValue(item.summary, "HIGH");
                  const active = item.status === "QUEUED" || item.status === "RUNNING";
                  const outcomeUnavailable = item.status === "ERROR" && Object.keys(item.summary ?? {}).length === 0;
                  return (
                    <article className={detailJob?.id === item.id ? "selected" : ""} key={item.id}>
                      <header><div className={`reports-source-icon ${item.target_type}`}>{sourceIcon(item.target_type)}</div><span><strong title={item.target}>{item.target}</strong><small>{sourceLabel(item.target_type)} · {formatDateTime(item.created_at)}</small></span><span className={`badge ${statusClass(item.status)}`}>{item.status}</span></header>
                      <dl><div><dt>Priority</dt><dd>{active ? "Pending" : outcomeUnavailable ? "Unavailable" : priority}</dd></div><div><dt>Findings</dt><dd>{active || outcomeUnavailable ? "—" : summaryTotal(item.summary)}</dd></div><div><dt>Files</dt><dd>{active || outcomeUnavailable ? "—" : formatNumber(item.coverage?.files_scanned)}</dd></div></dl>
                      <button type="button" onClick={(event) => void openDetails(item, event.currentTarget)}>View report details <ChevronRight size={16} /></button>
                    </article>
                  );
                })}</div>

                <footer className="reports-history-footer">
                  <span>Showing {start + 1}–{Math.min(start + pageSize, filteredJobs.length)} of {filteredJobs.length}</span>
                  <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={setPage} label="Report history pages" />
                </footer>
              </>
            )}
          </section>
        </>
      )}

      {detailJob && activeDetailJob && (
        <ReportDetailDrawer
          job={activeDetailJob}
          report={coherentDetailReport}
          loading={detailOpening || detailTransitioning}
          error={detailError}
          exportBlocked={exportBlocked}
          exportOpening={exportOpening}
          exportError={exportError}
          reviewBlocked={reviewBlocked}
          onClose={closeDetails}
          onRetry={retryDetails}
          onExport={(format) => void openVerifiedExport(format)}
          onReviewFindings={() => coherentDetailReport && onReviewFindings(activeDetailJob, coherentDetailReport)}
        />
      )}
    </section>
  );
}

function ReportsMetric({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: number; detail: string; tone: string }) {
  return <article className={`reports-metric ${tone}`}><div><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{detail}</small></article>;
}

function ReportsLoadingState() {
  return (
    <div className="reports-loading" role="status" aria-label="Loading report history">
      <div className="reports-loading-metrics">{Array.from({ length: 4 }, (_, index) => <span key={index} />)}</div>
      <div className="reports-loading-table"><i /><i /><i /><i /><i /></div>
    </div>
  );
}

function ReportsEmptyState({ icon, title, detail, action }: { icon: ReactNode; title: string; detail: string; action: ReactNode }) {
  return <div className="reports-empty"><div>{icon}</div><strong>{title}</strong><p>{detail}</p>{action}</div>;
}

function ReportDetailDrawer({ job, report, loading, error, exportBlocked, exportOpening, exportError, reviewBlocked, onClose, onRetry, onExport, onReviewFindings }: {
  job: ScanJob;
  report: ScanReport | null;
  loading: boolean;
  error: string;
  exportBlocked: boolean;
  exportOpening: keyof ScanJob["reports"] | null;
  exportError: string;
  reviewBlocked: boolean;
  onClose: () => void;
  onRetry: () => void;
  onExport: (format: keyof ScanJob["reports"]) => void;
  onReviewFindings: () => void;
}) {
  const active = job.status === "QUEUED" || job.status === "RUNNING";
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const verifiedJsonOnly = Boolean(job.error);
  const partialPolicyFailure = report?.status === "PARTIAL" && report.policy_failed === true;
  const savedReportOutcome = partialPolicyFailure
    ? "scanner coverage was incomplete and the policy threshold was reached"
    : report?.status === "PARTIAL"
      ? "scanner coverage was incomplete"
      : report?.policy_failed
        ? `${report.policy_fail_on ? `${report.policy_fail_on.toUpperCase()}+` : "the configured"} policy threshold was reached`
        : report?.status === "SUCCESS"
          ? "the security policy passed"
          : report?.status === "ERROR"
            ? "scanner execution failed"
            : "the assessment completed";
  const jobFailedAfterReport = job.status === "ERROR" && report?.status !== "ERROR";
  const outcomeTitle = jobFailedAfterReport
    ? "Job failed after report creation"
    : report?.status === "ERROR"
      ? "Scanner execution failed"
      : partialPolicyFailure
        ? "Coverage incomplete and policy threshold reached"
        : report?.status === "PARTIAL"
          ? "Scanner coverage incomplete"
          : report?.policy_failed
            ? "Policy threshold reached"
            : "Policy passed";
  const outcomeDetail = jobFailedAfterReport
    ? `A coherent report was saved first; it records that ${savedReportOutcome}. Review the job error and scanner diagnostics.`
    : report?.status === "ERROR"
      ? "The enabled scanner engines could not produce a successful assessment. Review the diagnostics below."
      : partialPolicyFailure
        ? `One or more scanners were incomplete, and the ${report?.policy_fail_on ? `${report.policy_fail_on.toUpperCase()}+` : "configured"} policy threshold was reached.`
        : report
          ? statusExplanation(report.status, report.policy_fail_on)
          : "";
  const priorityFindings = (report?.findings ?? [])
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => severityRank(right.finding.severity) - severityRank(left.finding.severity) || left.index - right.index)
    .slice(0, 5)
    .map(({ finding }) => finding);

  useEffect(() => {
    const closeButton = closeButtonRef.current;
    const drawer = closeButton?.closest(".report-detail-drawer");
    const activeElement = document.activeElement;
    const focusBecameDisabled = activeElement instanceof HTMLButtonElement && activeElement.disabled;
    if (closeButton && drawer && (!drawer.contains(activeElement) || focusBecameDisabled)) closeButton.focus();
  }, [loading, report, error, exportBlocked, exportOpening]);

  function trapFocus(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Tab") return;
    const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])'));
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="report-drawer-backdrop" onMouseDown={onClose}>
      <aside className="report-detail-drawer" role="dialog" aria-modal="true" aria-labelledby="report-detail-title" onKeyDown={trapFocus} onMouseDown={(event) => event.stopPropagation()}>
        <header className="report-drawer-head">
          <div><span className={`badge ${statusClass(job.status)}`}>{job.status}</span><small>Report details</small></div>
          <button ref={closeButtonRef} type="button" autoFocus onClick={onClose} aria-label="Close report details"><X size={20} /></button>
        </header>

        <div className="report-drawer-body">
          <section className="report-drawer-title">
            <div className={`reports-source-icon ${job.target_type}`}>{sourceIcon(job.target_type)}</div>
            <div><span>{sourceLabel(job.target_type)}</span><h2 id="report-detail-title" title={job.target}>{job.target}</h2><p>{statusExplanation(job.status, report?.policy_fail_on)}</p></div>
          </section>

          <dl className="report-job-details">
            <div><dt>Job ID</dt><dd title={job.id}>{job.id}</dd></div>
            <div><dt>Created</dt><dd>{formatDateTime(job.created_at)}</dd></div>
            <div><dt>Started</dt><dd>{job.started_at ? formatDateTime(job.started_at) : "Not started"}</dd></div>
            <div><dt>Duration</dt><dd>{active && job.started_at ? formatLiveDuration(job.started_at) : formatDuration(report?.metadata.duration_seconds ?? jobDuration(job))}</dd></div>
          </dl>

          {active && <div className="report-drawer-active" role="status"><Loader2 className="spin" size={18} /><span><strong>{job.status === "QUEUED" ? "Waiting for scanner capacity" : "Assessment in progress"}</strong><small>{job.progress_message || "Status updates will appear automatically."}</small></span></div>}
          {job.error && <div className="reports-inline-error drawer-error" role="alert"><AlertTriangle size={16} /><span>{job.error}</span></div>}

          {loading ? (
            <div className="report-detail-loading" role="status"><Loader2 className="spin" size={24} /><strong>Loading verified report</strong><span>Checking that the artifact belongs to this job…</span></div>
          ) : report ? (
            <>
              <section className={`report-policy-card ${job.status === "ERROR" || report.status === "ERROR" || report.policy_failed ? "failed" : report.status === "PARTIAL" ? "partial" : "success"}`}>
                <div>{job.status === "ERROR" || report.status === "ERROR" || report.policy_failed ? <AlertTriangle size={21} /> : <ShieldCheck size={21} />}</div>
                <span><small>Assessment outcome</small><strong>{outcomeTitle}</strong><p>{outcomeDetail}</p></span>
                <dl><div><dt>Job</dt><dd>{job.status}</dd></div><div><dt>Report</dt><dd>{report.status}</dd></div></dl>
              </section>

              <section className="report-drawer-section">
                <header><span>Risk summary</span><strong>{summaryTotal(report.summary)} findings</strong></header>
                <div className="report-severity-grid">{severityOrder.map((severity) => <div className={severity.toLowerCase()} key={severity}><span>{titleCase(severity)}</span><strong>{summaryValue(report.summary, severity)}</strong></div>)}</div>
              </section>

              <section className="report-drawer-section">
                <header><span>Coverage</span><strong>Candidate file census</strong></header>
                <div className="report-coverage-grid"><div><Files size={17} /><span><strong>{formatNumber(report.coverage.files_scanned)}</strong><small>Files</small></span></div><div><Code2 size={17} /><span><strong>{formatNumber(report.coverage.lines_scanned)}</strong><small>Lines</small></span></div><div><HardDrive size={17} /><span><strong>{report.coverage.bytes_scanned == null ? "—" : formatFileSize(safeNumber(report.coverage.bytes_scanned))}</strong><small>Source size</small></span></div></div>
              </section>

              <section className="report-drawer-section report-engine-section">
                <header><span>Scanner health</span><strong>{report.scanners.length} reported</strong></header>
                <ScannerHealthDashboard report={report} />
              </section>

              <ScanDiagnostics report={report} />

              <section className="report-drawer-section">
                <header><span>Priority findings</span><strong>{priorityFindings.length ? `Top ${priorityFindings.length}` : "None included"}</strong></header>
                {priorityFindings.length ? <div className="report-priority-list">{priorityFindings.map((finding, index) => <article key={`${finding.finding_id}-${index}`}><span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><small>{finding.rule_id ?? finding.cve ?? finding.scanner} · {finding.file ?? "Location unavailable"}{finding.line_start ? `:${finding.line_start}` : ""}</small></div></article>)}</div> : <div className="report-drawer-empty"><ShieldCheck size={21} />No findings were included in this report.</div>}
              </section>

              <section className="report-export-card">
                <div><Download size={19} /><span><strong>Export verified report</strong><small>{exportOpening ? "Capturing and verifying the selected export before it opens." : exportBlocked ? "Paused while ownership is rechecked or another scan is active." : verifiedJsonOnly ? "This incomplete job exposes verified JSON only." : "Every export is captured between two ownership checks."}</small></span></div>
                <div>
                  <button type="button" disabled={exportBlocked || Boolean(exportOpening) || verifiedJsonOnly} title={verifiedJsonOnly ? "Unavailable because this job did not complete every report format." : undefined} onClick={() => onExport("html")}>{exportOpening === "html" ? "Verifying…" : "Open HTML"}</button>
                  <button type="button" disabled={exportBlocked || Boolean(exportOpening) || verifiedJsonOnly} title={verifiedJsonOnly ? "Unavailable because this job did not complete every report format." : undefined} onClick={() => onExport("pdf")}>{exportOpening === "pdf" ? "Verifying…" : "Download PDF"}</button>
                  <button type="button" disabled={exportBlocked || Boolean(exportOpening)} onClick={() => onExport("json")}>{exportOpening === "json" ? "Verifying…" : "Open JSON"}</button>
                  <button type="button" disabled={exportBlocked || Boolean(exportOpening) || verifiedJsonOnly} title={verifiedJsonOnly ? "Unavailable because this job did not complete every report format." : undefined} onClick={() => onExport("sarif")}>{exportOpening === "sarif" ? "Verifying…" : "Open SARIF"}</button>
                </div>
                {exportError && <div className="report-export-error" role="alert"><AlertTriangle size={14} />{exportError}</div>}
                <p><CircleAlert size={14} />{exportBlocked ? "Export will unlock after ownership is verified. The report details remain available for review." : verifiedJsonOnly ? "HTML, PDF, and SARIF are disabled because they may be incomplete or left over from an earlier scan." : "The captured file cannot change if the backend replaces its shared paths afterward."}</p>
              </section>

              <button
                type="button"
                className="report-review-button"
                onClick={onReviewFindings}
                disabled={reviewBlocked}
                title={reviewBlocked ? "Wait for the active scan to finish before replacing the findings workspace." : undefined}
              >
                <Bug size={17} /> Open all findings <ArrowRight size={16} />
              </button>
              {reviewBlocked && <p className="report-review-note" role="status"><CircleAlert size={14} />A different scan is active. Keep this report open for review, then open all findings after that scan finishes.</p>}
            </>
          ) : !active ? (
            <div className="report-detail-unavailable" role="alert"><div><FileJson size={23} /></div><span><strong>Verified report unavailable</strong><p>{error || "No report matching this job is currently available. A newer scan may have replaced the shared artifact."}</p></span><button type="button" onClick={onRetry}><RefreshCcw size={15} /> Retry</button></div>
          ) : null}
        </div>
      </aside>
    </div>
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

function Pagination({ currentPage, totalPages, onPageChange, label = "Pagination" }: { currentPage: number; totalPages: number; onPageChange: (page: number) => void; label?: string }) {
  const pages = paginationRange(currentPage, totalPages);
  return (
    <nav className="pagination" aria-label={label}>
      <button disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)} aria-label="Previous page">
        <ChevronRight className="flip" size={17} />
      </button>
      {pages.map((page, index) =>
        page === "..."
          ? <span key={`ellipsis-${index}`}>...</span>
          : (
            <button key={page} className={page === currentPage ? "active" : ""} aria-current={page === currentPage ? "page" : undefined} onClick={() => onPageChange(page)}>
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

function NavButton({ active, icon, children, onClick }: { active: boolean; icon: ReactNode; children: ReactNode; onClick: () => void }) {
  const label = typeof children === "string" ? children : undefined;
  return (
    <button type="button" className={active ? "active" : ""} aria-current={active ? "page" : undefined} aria-label={label} data-label={label} title={label} onClick={onClick}>
      {icon}
      <span className="nav-label">{children}</span>
    </button>
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

const archiveSuffixes = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tar", ".tgz", ".tbz2", ".txz", ".7z", ".rar", ".gz", ".bz2", ".xz"];

function isArchiveName(name: string): boolean {
  const normalized = name.trim().toLowerCase();
  return archiveSuffixes.some((suffix) => normalized.endsWith(suffix));
}

function validateScanInput(targetType: TargetType, githubUrl: string, localPath: string, singleFile: File | null, folderFiles: File[], zipFile: File | null): string {
  if (targetType === "github") {
    if (!githubUrl.trim()) return "Enter a public GitHub repository URL.";
    if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(githubUrl.trim())) return "Use a repository URL in the form https://github.com/owner/repository.";
  }
  if (targetType === "local_path" && !localPath.trim()) return "Enter a file or folder path inside the scanner API workspace.";
  if (targetType === "file" && !singleFile) return "Choose one source file before starting the scan.";
  if (targetType === "file" && singleFile && isArchiveName(singleFile.name)) return "Use ZIP archive for .zip files, or extract other archives and choose Project folder.";
  if (targetType === "folder" && folderFiles.length === 0) return "Choose a project folder before starting the scan.";
  if (targetType === "zip" && !zipFile) return "Choose one .zip archive before starting the scan.";
  if (targetType === "zip" && zipFile && !zipFile.name.toLowerCase().endsWith(".zip")) return "Only .zip archives are supported for archive scans.";
  return "";
}

function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "Size unavailable";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function folderRootName(files: File[]): string {
  const relativePath = (files[0] as File & { webkitRelativePath?: string } | undefined)?.webkitRelativePath;
  return relativePath?.split(/[\\/]/).filter(Boolean)[0] ?? "";
}

function summarizeFileExtensions(files: File[]): string[] {
  const counts = new Map<string, number>();
  for (const file of files) {
    const name = file.name.toLowerCase();
    const extension = name.includes(".") ? `.${name.split(".").pop()}` : "no extension";
    counts.set(extension, (counts.get(extension) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 6)
    .map(([extension, count]) => `${extension} ${count}`);
}

function countFileExtensions(files: File[]): number {
  return new Set(files.map((file) => {
    const name = file.name.toLowerCase();
    return name.includes(".") ? name.split(".").pop() : "no extension";
  })).size;
}

function formatLiveDuration(startedAt: string): string {
  const started = safeDate(startedAt);
  if (!started) return "—";
  return formatDuration(Math.max(0, (Date.now() - started) / 1000));
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
    rules: "Review configured OpenGrep rules and scanner coverage metadata.",
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
