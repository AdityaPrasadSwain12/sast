export type TargetType = "github" | "file" | "folder" | "zip" | "local_path";

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
    final_report_finding_count?: number;
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
  description?: string | null;
  severity: Severity;
  confidence?: string | null;
  file: string | null;
  line_start: number | null;
  line_end?: number | null;
  column_start?: number | null;
  column_end?: number | null;
  code_snippet?: string | null;
  package?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  remediation: string | null;
  cve: string | null;
  cwe: string[];
  owasp?: string[];
  cvss?: number | null;
  secret_type?: string | null;
  references?: string[];
}

export interface ScanReport {
  metadata: {
    scan_id: string;
    target: string;
    target_kind?: string;
    started_at?: string;
    duration_seconds: number;
    scanner_versions: Record<string, string>;
  };
  status: ScanJob["status"];
  policy_failed?: boolean;
  policy_fail_on?: string;
  summary: Record<string, number>;
  coverage: ScanJob["coverage"] & {
    extensions?: Record<string, number>;
    bytes_scanned?: number;
    binary_files_skipped_for_line_count?: number;
  };
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
  errors?: string[];
  warnings?: string[];
}
