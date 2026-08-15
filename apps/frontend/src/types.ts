export type TargetType = "github" | "file" | "folder" | "local_path";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";

export interface ScanJob {
  id: string;
  target_type: TargetType;
  target: string;
  status: "QUEUED" | "RUNNING" | "SUCCESS" | "FAILED" | "PARTIAL" | "ERROR";
  progress_message: string;
  summary: Record<string, number>;
  coverage: {
    files_scanned?: number;
    lines_scanned?: number;
    languages?: Record<string, number>;
  };
  integrity: {
    scanner_raw_finding_count?: number;
    scanner_parsed_finding_count?: number;
    dropped_finding_count?: number;
    all_parsed_findings_included?: boolean;
  };
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  reports: {
    json: string;
    html: string;
    sarif: string;
    pdf: string;
  };
}

export interface Finding {
  finding_id: string;
  scanner: string;
  category: string;
  rule_id: string | null;
  title: string;
  severity: Severity;
  file: string | null;
  line_start: number | null;
  remediation: string | null;
  cve: string | null;
  cwe: string[];
}

export interface ScanReport {
  metadata: {
    scan_id: string;
    target: string;
    duration_seconds: number;
    scanner_versions: Record<string, string>;
  };
  status: ScanJob["status"];
  summary: Record<string, number>;
  coverage: ScanJob["coverage"];
  integrity: ScanJob["integrity"];
  scanners: Array<{
    scanner: string;
    status: string;
    version: string | null;
    raw_finding_count: number;
    parsed_finding_count: number;
    dropped_finding_count: number;
    duration_seconds: number;
  }>;
  findings: Finding[];
}
