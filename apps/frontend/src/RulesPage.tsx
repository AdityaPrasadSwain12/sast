import {
  KeyboardEvent as ReactKeyboardEvent,
  RefObject,
  ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  Braces,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Code2,
  Copy,
  Database,
  ExternalLink,
  FileCode2,
  Filter,
  Gauge,
  Layers3,
  ListChecks,
  LockKeyhole,
  PackageSearch,
  Play,
  RefreshCcw,
  RotateCcw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  X
} from "lucide-react";


type RulesTab = "configured" | "community" | "custom" | "inactive";
type RuleSort = "pack" | "severity" | "name";

interface CatalogRule {
  key: string;
  id: string;
  title: string;
  description: string;
  severity: string;
  languages: string[];
  category: string;
  mode: string;
  confidence?: string;
  likelihood?: string;
  impact?: string;
  subcategory?: string;
  cwe: string[];
  owasp: string[];
  technologies?: string[];
  references?: string[];
  remediation?: string;
  pack: string;
  source: "community" | "custom";
  path: string;
  configured: boolean;
  duplicate_count: number;
}

interface RuleCatalog {
  schema_version: number;
  generated_from: string;
  counting_method: string;
  config_sha256: string;
  rule_revision: string | null;
  summary: {
    configured_production_rules: number;
    raw_configured_rule_entries: number;
    excluded_fixture_rules: number;
    excluded_fixture_files: number;
    inactive_bundled_rules: number;
    configured_rule_files: number;
    catalogued_rule_files: number;
    configured_community_sources: number;
    configured_custom_sources: number;
    duplicate_configured_rule_ids: number;
    severity_counts: Record<string, number>;
    mode_counts: Record<string, number>;
    pack_counts: Record<string, number>;
  };
  configuration: {
    auto_select_rule_sources: boolean;
    policy_fail_on: string;
    opengrep_image: string;
    opengrep_timeout_seconds: number;
    trivy_image: string;
    trivy_timeout_seconds: number;
    trivy_scanners: string[];
    configured_sources: string[];
    inactive_bundled_packs: string[];
  };
  rules: CatalogRule[];
}

interface ChartEntry { label: string; value: number; color: string }

const baseUrl = import.meta.env.BASE_URL || "/";
const catalogUrl = `${baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`}rules-catalog.json`;
let cachedCatalog: RuleCatalog | null = null;
let catalogRequest: Promise<RuleCatalog> | null = null;
const pageSize = 12;
const nativeSeverityOrder = ["ERROR", "WARNING", "INFO", "LOW", "UNKNOWN"];
const severityDetails: Record<string, { normalized: string; color: string; rank: number }> = {
  ERROR: { normalized: "HIGH", color: "#dc2626", rank: 4 },
  WARNING: { normalized: "MEDIUM", color: "#d97706", rank: 3 },
  LOW: { normalized: "LOW", color: "#16a34a", rank: 2 },
  INFO: { normalized: "INFO", color: "#2563eb", rank: 1 },
  UNKNOWN: { normalized: "UNKNOWN", color: "#94a3b8", rank: 0 }
};

const languageAliases: Record<string, string> = {
  "c#": "C#",
  csharp: "C#",
  javascript: "JavaScript",
  js: "JavaScript",
  typescript: "TypeScript",
  ts: "TypeScript",
  kotlin: "Kotlin",
  kt: "Kotlin",
  bash: "Shell",
  sh: "Shell",
  hcl: "Terraform / HCL",
  terraform: "Terraform / HCL",
  generic: "Generic / Regex",
  regex: "Generic / Regex"
};

export default function RulesPage({ onNewScan }: { onNewScan: () => void }) {
  const [catalog, setCatalog] = useState<RuleCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [tab, setTab] = useState<RulesTab>("configured");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [languageFilter, setLanguageFilter] = useState("ALL");
  const [modeFilter, setModeFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [sort, setSort] = useState<RuleSort>("pack");
  const [page, setPage] = useState(1);
  const [selectedRule, setSelectedRule] = useState<CatalogRule | null>(null);
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);
  const pageHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const catalogRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError("");
    loadRuleCatalog(reloadToken > 0)
      .then((payload) => {
        if (!cancelled) setCatalog(payload);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setCatalog(null);
        setLoadError(error instanceof Error ? error.message : "The generated rule catalogue could not be loaded.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  const languageOptions = useMemo(() => {
    const values = new Set<string>();
    catalog?.rules.forEach((rule) => rule.languages.forEach((language) => values.add(displayLanguage(language))));
    return Array.from(values).sort((left, right) => left.localeCompare(right));
  }, [catalog]);

  const categoryOptions = useMemo(() => {
    const values = new Set(catalog?.rules.map((rule) => formatCategory(rule.category)) ?? []);
    return Array.from(values).sort((left, right) => left.localeCompare(right));
  }, [catalog]);

  const filteredRules = useMemo(() => {
    if (!catalog) return [];
    const normalizedQuery = query.trim().toLowerCase();
    return catalog.rules
      .filter((rule) => {
        if (tab === "configured") return rule.configured;
        if (tab === "community") return rule.configured && rule.source === "community";
        if (tab === "custom") return rule.configured && rule.source === "custom";
        return !rule.configured;
      })
      .filter((rule) => severityFilter === "ALL" || rule.severity === severityFilter)
      .filter((rule) => languageFilter === "ALL" || rule.languages.some((language) => displayLanguage(language) === languageFilter))
      .filter((rule) => modeFilter === "ALL" || rule.mode === modeFilter)
      .filter((rule) => categoryFilter === "ALL" || formatCategory(rule.category) === categoryFilter)
      .filter((rule) => {
        if (!normalizedQuery) return true;
        return [
          rule.id,
          rule.title,
          rule.description,
          rule.pack,
          rule.path,
          rule.category,
          ...rule.languages,
          ...rule.languages.map(displayLanguage),
          ...rule.cwe,
          ...rule.owasp,
          ...(rule.technologies ?? [])
        ].some((value) => value.toLowerCase().includes(normalizedQuery));
      })
      .sort((left, right) => {
        if (sort === "severity") {
          const difference = severityRank(right.severity) - severityRank(left.severity);
          if (difference) return difference;
        }
        if (sort === "name") return left.id.localeCompare(right.id) || left.path.localeCompare(right.path);
        return formatPack(left.pack).localeCompare(formatPack(right.pack)) || left.id.localeCompare(right.id) || left.path.localeCompare(right.path);
      });
  }, [catalog, tab, query, severityFilter, languageFilter, modeFilter, categoryFilter, sort]);

  const totalPages = Math.max(1, Math.ceil(filteredRules.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const visibleRules = filteredRules.slice(start, start + pageSize);
  const filtersActive = Boolean(query || severityFilter !== "ALL" || languageFilter !== "ALL" || modeFilter !== "ALL" || categoryFilter !== "ALL" || sort !== "pack");

  useEffect(() => setPage(1), [tab, query, severityFilter, languageFilter, modeFilter, categoryFilter, sort]);

  useEffect(() => {
    if (!selectedRule) return;
    const previousOverflow = document.body.style.overflow;
    const appShell = document.querySelector<HTMLElement>(".app-shell");
    const appShellWasInert = appShell?.hasAttribute("inert") ?? false;
    const previousAriaHidden = appShell?.getAttribute("aria-hidden");
    document.body.style.overflow = "hidden";
    appShell?.setAttribute("inert", "");
    appShell?.setAttribute("aria-hidden", "true");
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRule();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      if (appShell) {
        if (!appShellWasInert) appShell.removeAttribute("inert");
        if (previousAriaHidden == null) appShell.removeAttribute("aria-hidden");
        else appShell.setAttribute("aria-hidden", previousAriaHidden);
      }
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [selectedRule]);

  function openRule(rule: CatalogRule, trigger: HTMLButtonElement) {
    detailTriggerRef.current = trigger;
    setSelectedRule(rule);
  }

  function closeRule() {
    setSelectedRule(null);
    window.setTimeout(() => {
      if (detailTriggerRef.current?.isConnected && isElementVisible(detailTriggerRef.current)) detailTriggerRef.current.focus();
      else pageHeadingRef.current?.focus();
    }, 0);
  }

  function clearFilters() {
    setQuery("");
    setSeverityFilter("ALL");
    setLanguageFilter("ALL");
    setModeFilter("ALL");
    setCategoryFilter("ALL");
    setSort("pack");
  }

  function showCustomRules() {
    setTab("custom");
    clearFilters();
    window.setTimeout(() => catalogRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  }

  return (
    <section className="rules-page" aria-busy={loading}>
      <section className="rules-hero">
        <div className="rules-hero-copy">
          <span className="rules-kicker"><Braces size={15} /> Detection catalogue</span>
          <h2 ref={pageHeadingRef} tabIndex={-1}>Rules Library</h2>
          <p>Explore the repository’s configured OpenGrep definitions, security mappings, language coverage, and bundled packs.</p>
          <div className="rules-hero-meta">
            <span><Database size={14} />Generated from repository rules</span>
            {catalog?.rule_revision && <span title={catalog.rule_revision}><Code2 size={14} />Revision {catalog.rule_revision.slice(0, 8)}</span>}
            <span><Shield size={14} />Trivy coverage is managed dynamically</span>
          </div>
        </div>
        <div className="rules-hero-actions">
          <button type="button" className="rules-secondary-action" onClick={showCustomRules} disabled={!catalog}><FileCode2 size={17} /> Custom Rules</button>
          <button type="button" className="rules-primary-action" onClick={onNewScan}><Play size={17} /> New Scan</button>
        </div>
      </section>

      {loading && !catalog ? (
        <RulesLoadingState />
      ) : loadError || !catalog ? (
        <section className="rules-load-error" role="alert">
          <div><CircleAlert size={28} /></div>
          <div><strong>Rule catalogue unavailable</strong><p>{loadError || "The generated catalogue could not be loaded."}</p></div>
          <button type="button" onClick={() => setReloadToken((token) => token + 1)}><RefreshCcw size={16} /> Try again</button>
        </section>
      ) : (
        <RulesContent
          catalog={catalog}
          tab={tab}
          setTab={setTab}
          query={query}
          setQuery={setQuery}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          languageFilter={languageFilter}
          setLanguageFilter={setLanguageFilter}
          modeFilter={modeFilter}
          setModeFilter={setModeFilter}
          categoryFilter={categoryFilter}
          setCategoryFilter={setCategoryFilter}
          sort={sort}
          setSort={setSort}
          languageOptions={languageOptions}
          categoryOptions={categoryOptions}
          filteredRules={filteredRules}
          visibleRules={visibleRules}
          filtersActive={filtersActive}
          clearFilters={clearFilters}
          currentPage={currentPage}
          totalPages={totalPages}
          start={start}
          setPage={setPage}
          openRule={openRule}
          catalogRef={catalogRef}
        />
      )}

      {selectedRule && <RuleDetailDrawer rule={selectedRule} onClose={closeRule} />}
    </section>
  );
}

function RulesContent({
  catalog,
  tab,
  setTab,
  query,
  setQuery,
  severityFilter,
  setSeverityFilter,
  languageFilter,
  setLanguageFilter,
  modeFilter,
  setModeFilter,
  categoryFilter,
  setCategoryFilter,
  sort,
  setSort,
  languageOptions,
  categoryOptions,
  filteredRules,
  visibleRules,
  filtersActive,
  clearFilters,
  currentPage,
  totalPages,
  start,
  setPage,
  openRule,
  catalogRef
}: {
  catalog: RuleCatalog;
  tab: RulesTab;
  setTab: (tab: RulesTab) => void;
  query: string;
  setQuery: (value: string) => void;
  severityFilter: string;
  setSeverityFilter: (value: string) => void;
  languageFilter: string;
  setLanguageFilter: (value: string) => void;
  modeFilter: string;
  setModeFilter: (value: string) => void;
  categoryFilter: string;
  setCategoryFilter: (value: string) => void;
  sort: RuleSort;
  setSort: (value: RuleSort) => void;
  languageOptions: string[];
  categoryOptions: string[];
  filteredRules: CatalogRule[];
  visibleRules: CatalogRule[];
  filtersActive: boolean;
  clearFilters: () => void;
  currentPage: number;
  totalPages: number;
  start: number;
  setPage: (page: number) => void;
  openRule: (rule: CatalogRule, trigger: HTMLButtonElement) => void;
  catalogRef: RefObject<HTMLElement | null>;
}) {
  const summary = catalog.summary;
  const configuredRules = catalog.rules.filter((rule) => rule.configured);
  const customRuleCount = configuredRules.filter((rule) => rule.source === "custom").length;
  const severityEntries = nativeSeverityOrder
    .map((severity) => ({
      label: severity,
      value: summary.severity_counts[severity] ?? 0,
      color: severityDetails[severity]?.color ?? severityDetails.UNKNOWN.color
    }))
    .filter((entry) => entry.value > 0);
  const packEntries = topPackEntries(summary.pack_counts);
  const configuredCount = summary.configured_production_rules;
  const tabCounts: Record<RulesTab, number> = {
    configured: configuredCount,
    community: configuredCount - customRuleCount,
    custom: customRuleCount,
    inactive: summary.inactive_bundled_rules
  };
  const baseRules = (summary.pack_counts.generic ?? 0) + (summary.pack_counts["problem-based-packs"] ?? 0) + customRuleCount;
  const inactivePackNames = catalog.configuration.inactive_bundled_packs.map(formatPack);
  const inactivePackLabel = formatList(inactivePackNames);

  return (
    <>
      <div className="rules-metrics" aria-label="Rule catalogue summary">
        <RulesMetric icon={<ShieldCheck size={18} />} label="Production definitions" value={configuredCount} detail="Configured catalogue scope" tone="blue" />
        <RulesMetric icon={<Layers3 size={18} />} label="Community sources" value={summary.configured_community_sources} detail="Configured language and problem packs" tone="violet" />
        <RulesMetric icon={<FileCode2 size={18} />} label="Custom rules" value={customRuleCount} detail="Project-owned gap coverage" tone="green" />
        <RulesMetric icon={<Gauge size={18} />} label="Taint rules" value={summary.mode_counts.taint ?? 0} detail="Data-flow definitions" tone="orange" />
        <RulesMetric icon={<Sparkles size={18} />} label="Bundled, inactive" value={summary.inactive_bundled_rules} detail={`${inactivePackLabel || "Additional"} packs`} tone="amber" />
      </div>

      <div className="rules-insights-grid">
        <section className="rules-insight-card rules-severity-card">
          <RulesSectionHeader eyebrow="Native severity" title="Rule distribution" description="OpenGrep labels with application normalization." icon={<Shield size={18} />} />
          <RuleSeverityChart entries={severityEntries} total={configuredCount} />
          <div className="rules-mode-strip" aria-label="Rule mode summary">
            <div><Braces size={16} /><span><strong>{formatNumber(summary.mode_counts.search)}</strong><small>Search / pattern</small></span></div>
            <div><ListChecks size={16} /><span><strong>{formatNumber(summary.mode_counts.taint)}</strong><small>Taint / data flow</small></span></div>
          </div>
        </section>

        <section className="rules-insight-card rules-pack-card">
          <RulesSectionHeader eyebrow="Configured scope" title="Largest rule packs" description="Top five packs; remaining definitions are grouped." icon={<Layers3 size={18} />} />
          <RulePackBars entries={packEntries} total={configuredCount} />
          <p className="rules-card-footnote">Configured does not mean loaded on every scan; automatic selection depends on the detected target languages.</p>
        </section>

        <section className="rules-insight-card rules-runtime-card">
          <RulesSectionHeader eyebrow="Engine configuration" title="Detection stack" description="Repository configuration, not runtime telemetry." icon={<Database size={18} />} />
          <div className="rules-runtime-list">
            <article><div className="opengrep"><Braces size={17} /></div><span><strong>OpenGrep</strong><small>{summary.configured_community_sources} community sources + custom</small></span><i>Configured</i></article>
            <article><div className="trivy"><PackageSearch size={17} /></div><span><strong>Trivy</strong><small>{catalog.configuration.trivy_scanners.map(formatCategory).join(" · ")}</small></span><i>Managed</i></article>
            <article><div className="policy"><LockKeyhole size={17} /></div><span><strong>Policy threshold</strong><small>Findings at {catalog.configuration.policy_fail_on}+ fail policy</small></span><i>{catalog.configuration.policy_fail_on}+</i></article>
          </div>
          <p className="rules-card-footnote">Trivy advisory and check counts are dynamic and are not exposed by the current API.</p>
        </section>
      </div>

      <div className="rules-notices">
        <article className="rules-notice info"><div><CheckCircle2 size={19} /></div><div><strong>Automatic source selection is {catalog.configuration.auto_select_rule_sources ? "enabled" : "disabled"}</strong><p>{catalog.configuration.auto_select_rule_sources ? `${formatNumber(baseRules)} generic, problem-pack, and custom definitions are always considered; detected language packs are then added.` : "Configured sources are passed to OpenGrep without target-language source selection."}</p></div></article>
        <article className="rules-notice warning"><div><AlertTriangle size={19} /></div><div><strong>Coverage configuration needs review</strong><p>{inactivePackLabel || "Additional packs"} {inactivePackNames.length === 1 ? "is" : "are"} bundled but not configured, and several mixed-language extensions do not map cleanly into automatic selection.</p></div></article>
      </div>

      <section className="rules-catalog-card" ref={catalogRef}>
        <header className="rules-catalog-head">
          <div><span>Generated static catalogue</span><h3>OpenGrep rule definitions</h3><p>Search production metadata and inspect bundled packs without modifying scanner configuration.</p></div>
          <strong aria-live="polite">{formatNumber(filteredRules.length)} {filteredRules.length === 1 ? "result" : "results"}</strong>
        </header>

        <div className="rules-tabs" role="group" aria-label="Filter rules by source">
          {([
            ["configured", "Configured"],
            ["community", "Community"],
            ["custom", "Custom"],
            ["inactive", "Bundled, inactive"]
          ] as Array<[RulesTab, string]>).map(([value, label]) => (
            <button key={value} type="button" aria-pressed={tab === value} className={tab === value ? "active" : ""} onClick={() => setTab(value)}>
              {label}<span>{formatNumber(tabCounts[value])}</span>
            </button>
          ))}
        </div>

        <div className="rules-toolbar">
          <label className="rules-search"><Search size={17} /><span className="sr-only">Search rule catalogue</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule ID, title, CWE, OWASP, language…" /></label>
          <label><span className="sr-only">Filter by native severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="ALL">All severities</option>{nativeSeverityOrder.filter((severity) => catalog.summary.severity_counts[severity]).map((severity) => <option value={severity} key={severity}>{severity} · {normalizedSeverity(severity)}</option>)}</select></label>
          <label><span className="sr-only">Filter by language</span><select value={languageFilter} onChange={(event) => setLanguageFilter(event.target.value)}><option value="ALL">All languages</option>{languageOptions.map((language) => <option value={language} key={language}>{language}</option>)}</select></label>
          <label><span className="sr-only">Filter by mode</span><select value={modeFilter} onChange={(event) => setModeFilter(event.target.value)}><option value="ALL">All modes</option><option value="search">Search / pattern</option><option value="taint">Taint / data flow</option></select></label>
          <label><span className="sr-only">Filter by category</span><select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}><option value="ALL">All categories</option>{categoryOptions.map((category) => <option value={category} key={category}>{category}</option>)}</select></label>
          <label><span className="sr-only">Sort rules</span><select value={sort} onChange={(event) => setSort(event.target.value as RuleSort)}><option value="pack">Pack and rule ID</option><option value="severity">Highest severity</option><option value="name">Rule ID A–Z</option></select></label>
          {filtersActive && <button type="button" className="rules-clear-button" onClick={clearFilters}><RotateCcw size={15} /> Clear</button>}
        </div>

        {filteredRules.length === 0 ? (
          <div className="rules-empty"><div><Filter size={26} /></div><strong>No rules match these filters</strong><p>Change the search or filters to return to the available catalogue.</p><button type="button" onClick={clearFilters}><RotateCcw size={16} /> Clear filters</button></div>
        ) : (
          <>
            <div className="rules-table-wrap" tabIndex={0} aria-label="Rule catalogue table; scroll horizontally if needed">
              <table className="rules-table">
                <caption className="sr-only">Searchable OpenGrep rule catalogue</caption>
                <thead><tr><th>Severity</th><th>Rule</th><th>Language</th><th>Source</th><th>Category / Mode</th><th>Security mapping</th><th><span className="sr-only">Action</span></th></tr></thead>
                <tbody>{visibleRules.map((rule) => <RuleTableRow rule={rule} key={rule.key} onOpen={openRule} />)}</tbody>
              </table>
            </div>
            <div className="rules-mobile-list">{visibleRules.map((rule) => <RuleMobileCard rule={rule} key={rule.key} onOpen={openRule} />)}</div>
            <footer className="rules-catalog-footer">
              <span>Showing {start + 1}–{Math.min(start + pageSize, filteredRules.length)} of {formatNumber(filteredRules.length)}</span>
              <RulesPagination currentPage={currentPage} totalPages={totalPages} onPageChange={setPage} />
            </footer>
          </>
        )}

        <div className="rules-catalog-disclosure">
          <CircleAlert size={15} />
          <span><strong>{formatNumber(summary.excluded_fixture_rules)} fixture definitions excluded.</strong> The production count omits {summary.excluded_fixture_files} test/fixed YAML files. Actual per-scan loaded rules are not recorded by the scanner.</span>
        </div>
      </section>
    </>
  );
}

function RulesMetric({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: number; detail: string; tone: string }) {
  return <article className={`rules-metric ${tone}`}><div><span>{label}</span><i>{icon}</i></div><strong>{formatNumber(value)}</strong><small>{detail}</small></article>;
}

function RulesSectionHeader({ eyebrow, title, description, icon }: { eyebrow: string; title: string; description: string; icon: ReactNode }) {
  return <header className="rules-section-head"><div>{icon}</div><div><small>{eyebrow}</small><strong>{title}</strong><p>{description}</p></div></header>;
}

function RuleSeverityChart({ entries, total }: { entries: ChartEntry[]; total: number }) {
  return (
    <div className="rules-severity-chart">
      <div className="rules-donut" role="img" aria-label={`${total} configured rule definitions by native severity`} style={{ background: donutGradient(entries, total) }}><div><strong>{formatNumber(total)}</strong><span>Definitions</span></div></div>
      <div className="rules-severity-legend">{entries.map((entry) => <div key={entry.label}><span><i style={{ background: entry.color }} />{entry.label}<small>→ {normalizedSeverity(entry.label)}</small></span><strong>{formatNumber(entry.value)}</strong></div>)}</div>
    </div>
  );
}

function RulePackBars({ entries, total }: { entries: Array<{ label: string; value: number }>; total: number }) {
  const maximum = Math.max(1, ...entries.map((entry) => entry.value));
  return <div className="rules-pack-bars">{entries.map((entry) => <div className="rules-pack-row" key={entry.label}><div><span>{entry.label}</span><strong>{formatNumber(entry.value)}<small>{Math.round((entry.value / total) * 100)}%</small></strong></div><div><i style={{ width: `${(entry.value / maximum) * 100}%` }} /></div></div>)}</div>;
}

function RuleTableRow({ rule, onOpen }: { rule: CatalogRule; onOpen: (rule: CatalogRule, trigger: HTMLButtonElement) => void }) {
  const languages = uniqueDisplayLanguages(rule.languages);
  return (
    <tr>
      <td><NativeSeverityBadge severity={rule.severity} /></td>
      <td><button type="button" className="rule-title-button" onClick={(event) => onOpen(rule, event.currentTarget)}><strong>{rule.title}</strong><span>{rule.id}{rule.duplicate_count > 1 ? ` · ${rule.duplicate_count} definitions share this ID` : ""}</span></button></td>
      <td><div className="rule-language-list">{languages.slice(0, 2).map((language) => <span key={language}>{language}</span>)}{languages.length > 2 && <i>+{languages.length - 2}</i>}</div></td>
      <td><span className="rule-source-cell"><strong>{formatPack(rule.pack)}</strong><small>{rule.configured ? "Configured source" : "Bundled, not configured"}</small></span></td>
      <td><span className="rule-category-cell"><strong>{formatCategory(rule.category)}</strong><small>{formatMode(rule.mode)}</small></span></td>
      <td><span className="rule-mapping-cell"><strong>{rule.cwe[0] ? compactMapping(rule.cwe[0]) : "—"}</strong><small>{rule.owasp[0] ? compactMapping(rule.owasp[0]) : "No OWASP metadata"}</small></span></td>
      <td><button type="button" className="rule-row-action" onClick={(event) => onOpen(rule, event.currentTarget)} aria-label={`View details for ${rule.id}`}>Details <ChevronRight size={16} /></button></td>
    </tr>
  );
}

function RuleMobileCard({ rule, onOpen }: { rule: CatalogRule; onOpen: (rule: CatalogRule, trigger: HTMLButtonElement) => void }) {
  return (
    <article>
      <header><NativeSeverityBadge severity={rule.severity} /><span className={`rule-config-state ${rule.configured ? "configured" : "inactive"}`}>{rule.configured ? "Configured" : "Inactive"}</span></header>
      <strong>{rule.title}</strong>
      <small>{rule.id}</small>
      <dl><div><dt>Source</dt><dd>{formatPack(rule.pack)}</dd></div><div><dt>Language</dt><dd>{uniqueDisplayLanguages(rule.languages).slice(0, 2).join(", ")}</dd></div><div><dt>Mode</dt><dd>{formatMode(rule.mode)}</dd></div></dl>
      <button type="button" onClick={(event) => onOpen(rule, event.currentTarget)}>View rule details <ChevronRight size={16} /></button>
    </article>
  );
}

function NativeSeverityBadge({ severity }: { severity: string }) {
  return <span className={`rule-severity-badge ${severity.toLowerCase()}`}><strong>{severity}</strong><small>{normalizedSeverity(severity)}</small></span>;
}

function RuleDetailDrawer({ rule, onClose }: { rule: CatalogRule; onClose: () => void }) {
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const [copied, setCopied] = useState<"id" | "path" | null>(null);
  const languages = uniqueDisplayLanguages(rule.languages);
  const safeReferences = (rule.references ?? []).filter(isSafeReference);

  function trapFocus(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Tab") return;
    const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])'));
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

  async function copyValue(kind: "id" | "path", value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(kind);
      window.setTimeout(() => setCopied((current) => current === kind ? null : current), 1800);
    } catch {
      setCopied(null);
    }
  }

  return createPortal(
    <div className="rule-drawer-backdrop" onMouseDown={onClose}>
      <aside className="rule-detail-drawer" role="dialog" aria-modal="true" aria-labelledby="rule-detail-title" onKeyDown={trapFocus} onMouseDown={(event) => event.stopPropagation()}>
        <header className="rule-drawer-head">
          <div><NativeSeverityBadge severity={rule.severity} /><span className="rule-drawer-context">{rule.configured ? "Configured definition" : "Bundled, not configured"}</span></div>
          <button ref={closeButtonRef} type="button" autoFocus onClick={onClose} aria-label="Close rule details"><X size={20} /></button>
        </header>
        <div className="rule-drawer-body">
          <section className="rule-drawer-title">
            <div><Braces size={21} /></div>
            <div><small>{formatPack(rule.pack)} · {formatMode(rule.mode)}</small><h2 id="rule-detail-title">{rule.title}</h2><code>{rule.id}</code></div>
          </section>

          {!rule.configured && <div className="rule-drawer-notice inactive"><Sparkles size={17} /><span><strong>This definition is not in the default configuration.</strong><small>It is bundled in the repository but will not be selected by current scans.</small></span></div>}
          {rule.duplicate_count > 1 && <div className="rule-drawer-notice warning"><AlertTriangle size={17} /><span><strong>Duplicate rule identifier</strong><small>{rule.duplicate_count} catalogue definitions share this ID. Review the source path before changing a rule.</small></span></div>}

          <section className="rule-detail-section rule-overview-section">
            <header><span>Rule overview</span><ShieldCheck size={17} /></header>
            <p>{rule.description || "No description is included in this rule's metadata."}</p>
            <div className="rule-copy-actions">
              <button type="button" onClick={() => void copyValue("id", rule.id)}>{copied === "id" ? <Check size={15} /> : <Copy size={15} />}{copied === "id" ? "Copied rule ID" : "Copy rule ID"}</button>
              <button type="button" onClick={() => void copyValue("path", rule.path)}>{copied === "path" ? <Check size={15} /> : <Copy size={15} />}{copied === "path" ? "Copied source path" : "Copy source path"}</button>
            </div>
          </section>

          <dl className="rule-detail-grid">
            <div><dt>Native severity</dt><dd>{rule.severity}</dd><small>Normalized {normalizedSeverity(rule.severity)}</small></div>
            <div><dt>Detection mode</dt><dd>{formatMode(rule.mode)}</dd><small>{rule.mode === "taint" ? "Data-flow analysis" : "Pattern matching"}</small></div>
            <div><dt>Metadata category</dt><dd>{formatCategory(rule.category)}</dd><small>Original rule metadata</small></div>
            <div><dt>Confidence</dt><dd>{rule.confidence ? formatCategory(rule.confidence) : "Unspecified"}</dd><small>Declared by the rule author</small></div>
            <div><dt>Subcategory</dt><dd>{rule.subcategory ? formatCategory(rule.subcategory) : "Unspecified"}</dd><small>Additional rule classification</small></div>
            <div><dt>Likelihood</dt><dd>{rule.likelihood ? formatCategory(rule.likelihood) : "Unspecified"}</dd><small>Declared exploit likelihood</small></div>
            <div><dt>Impact</dt><dd>{rule.impact ? formatCategory(rule.impact) : "Unspecified"}</dd><small>Declared security impact</small></div>
          </dl>

          <section className="rule-detail-section">
            <header><span>Languages and technology</span><Code2 size={17} /></header>
            <div className="rule-chip-list">{languages.map((language) => <span key={language}>{language}</span>)}{(rule.technologies ?? []).map((technology) => <span className="technology" key={technology}>{formatCategory(technology)}</span>)}</div>
          </section>

          <section className="rule-detail-section">
            <header><span>Security mapping</span><LockKeyhole size={17} /></header>
            {rule.cwe.length || rule.owasp.length ? <div className="rule-taxonomy"><div><strong>CWE</strong>{rule.cwe.length ? rule.cwe.map((item) => <span key={item}>{item}</span>) : <small>No CWE metadata</small>}</div><div><strong>OWASP</strong>{rule.owasp.length ? rule.owasp.map((item) => <span key={item}>{item}</span>) : <small>No OWASP metadata</small>}</div></div> : <div className="rule-detail-empty">No CWE or OWASP mapping is declared.</div>}
          </section>

          <section className="rule-detail-section">
            <header><span>Source definition</span><FileCode2 size={17} /></header>
            <dl className="rule-source-details"><div><dt>Pack</dt><dd>{formatPack(rule.pack)}</dd></div><div><dt>Source</dt><dd>{rule.source === "custom" ? "Project custom" : "OpenGrep community"}</dd></div><div><dt>Path</dt><dd title={rule.path}>{rule.path}</dd></div></dl>
            <p className="rule-source-note"><CircleAlert size={14} />Detection patterns remain in the source YAML and are intentionally not duplicated in this metadata view.</p>
          </section>

          <section className="rule-detail-section">
            <header><span>Remediation guidance</span><Shield size={17} /></header>
            <p>{rule.remediation || "This rule does not declare dedicated remediation text. Validate the finding context and follow the linked security guidance before applying a fix."}</p>
          </section>

          {safeReferences.length > 0 && <section className="rule-detail-section rule-reference-section"><header><span>References</span><ExternalLink size={17} /></header>{safeReferences.map((reference) => <a href={reference} target="_blank" rel="noreferrer" key={reference}><span>{reference}</span><ExternalLink size={14} /></a>)}</section>}
        </div>
      </aside>
    </div>,
    document.body
  );
}

function RulesLoadingState() {
  return <div className="rules-loading" role="status" aria-label="Loading rule catalogue"><div className="rules-loading-metrics">{Array.from({ length: 5 }, (_, index) => <span key={index} />)}</div><div className="rules-loading-insights"><i /><i /><i /></div><div className="rules-loading-table"><i /><i /><i /><i /><i /></div></div>;
}

function RulesPagination({ currentPage, totalPages, onPageChange }: { currentPage: number; totalPages: number; onPageChange: (page: number) => void }) {
  const pages = paginationRange(currentPage, totalPages);
  return (
    <nav className="rules-pagination" aria-label="Rule catalogue pages">
      <button type="button" disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)} aria-label="Previous page"><ChevronRight className="flip" size={17} /></button>
      {pages.map((page, index) => page === "…" ? <span key={`ellipsis-${index}`}>…</span> : <button type="button" key={page} className={page === currentPage ? "active" : ""} aria-current={page === currentPage ? "page" : undefined} onClick={() => onPageChange(page)}>{page}</button>)}
      <button type="button" disabled={currentPage === totalPages} onClick={() => onPageChange(currentPage + 1)} aria-label="Next page"><ChevronRight size={17} /></button>
    </nav>
  );
}

function topPackEntries(packCounts: Record<string, number>): Array<{ label: string; value: number }> {
  const sorted = Object.entries(packCounts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  const top = sorted.slice(0, 5).map(([pack, value]) => ({ label: formatPack(pack), value }));
  const other = sorted.slice(5).reduce((total, [, value]) => total + value, 0);
  if (other) top.push({ label: "Other packs", value: other });
  return top;
}

function donutGradient(entries: ChartEntry[], total: number): string {
  if (!total) return "conic-gradient(#e7edf5 0 100%)";
  let cursor = 0;
  const stops = entries.map((entry) => {
    const start = cursor;
    cursor += (entry.value / total) * 100;
    return `${entry.color} ${start}% ${cursor}%`;
  });
  return `conic-gradient(${stops.join(", ")})`;
}

function normalizedSeverity(severity: string): string {
  return severityDetails[severity.toUpperCase()]?.normalized ?? "UNKNOWN";
}

function severityRank(severity: string): number {
  return severityDetails[severity.toUpperCase()]?.rank ?? 0;
}

function displayLanguage(language: string): string {
  const normalized = language.trim();
  return languageAliases[normalized.toLowerCase()] ?? titleCase(normalized);
}

function uniqueDisplayLanguages(languages: string[]): string[] {
  return Array.from(new Set(languages.map(displayLanguage))).sort((left, right) => left.localeCompare(right));
}

function formatPack(pack: string): string {
  const normalized = pack.toLowerCase();
  if (normalized === "ai") return "AI";
  if (normalized === "ocaml") return "OCaml";
  if (normalized === "csharp") return "C#";
  if (normalized === "problem-based-packs") return "Problem-based packs";
  if (normalized === "custom") return "Custom gap rules";
  return titleCase(pack);
}

function formatMode(mode: string): string {
  if (mode.toLowerCase() === "taint") return "Taint / data flow";
  if (mode.toLowerCase() === "join") return "Join analysis";
  return "Search / pattern";
}

function formatCategory(value: string): string {
  return titleCase(value || "Uncategorized");
}

function compactMapping(value: string): string {
  const separator = value.indexOf(":");
  return separator > 0 ? value.slice(0, separator) : value;
}

function titleCase(value: string): string {
  return value.replace(/[_-]+/g, " ").toLowerCase().replace(/(^|\s)\w/g, (letter) => letter.toUpperCase());
}

function formatNumber(value: number | null | undefined): string {
  return Number.isFinite(Number(value)) ? Math.max(0, Number(value)).toLocaleString() : "—";
}

function paginationRange(current: number, total: number): Array<number | "…"> {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const values = new Set([1, total, current, current - 1, current + 1].filter((value) => value >= 1 && value <= total));
  const sorted = Array.from(values).sort((left, right) => left - right);
  const result: Array<number | "…"> = [];
  sorted.forEach((value, index) => {
    if (index && value - sorted[index - 1] > 1) result.push("…");
    result.push(value);
  });
  return result;
}

function isSafeReference(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function loadRuleCatalog(forceReload: boolean): Promise<RuleCatalog> {
  if (forceReload) {
    cachedCatalog = null;
    catalogRequest = null;
  }
  if (cachedCatalog) return Promise.resolve(cachedCatalog);
  if (!catalogRequest) {
    catalogRequest = fetch(catalogUrl, { cache: forceReload ? "reload" : "default" })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Rule catalogue request failed (${response.status}).`);
        return parseRuleCatalog(await response.json());
      })
      .then((catalog) => {
        cachedCatalog = catalog;
        return catalog;
      })
      .catch((error) => {
        catalogRequest = null;
        throw error;
      });
  }
  return catalogRequest;
}

function parseRuleCatalog(payload: unknown): RuleCatalog {
  if (!isRecord(payload) || payload.schema_version !== 1 || !Array.isArray(payload.rules) || !isRecord(payload.summary) || !isRecord(payload.configuration)) {
    throw new Error("The generated rule catalogue has an unsupported format.");
  }
  const summary = payload.summary;
  const configuration = payload.configuration;

  const summaryFields = [
    "configured_production_rules",
    "raw_configured_rule_entries",
    "excluded_fixture_rules",
    "excluded_fixture_files",
    "inactive_bundled_rules",
    "configured_rule_files",
    "catalogued_rule_files",
    "configured_community_sources",
    "configured_custom_sources",
    "duplicate_configured_rule_ids"
  ];
  const summaryValid = summaryFields.every((field) => isFiniteNumber(summary[field]))
    && isNumberRecord(summary.severity_counts)
    && isNumberRecord(summary.mode_counts)
    && isNumberRecord(summary.pack_counts);
  const configurationValid = typeof configuration.auto_select_rule_sources === "boolean"
    && typeof configuration.policy_fail_on === "string"
    && typeof configuration.opengrep_image === "string"
    && isFiniteNumber(configuration.opengrep_timeout_seconds)
    && typeof configuration.trivy_image === "string"
    && isFiniteNumber(configuration.trivy_timeout_seconds)
    && isStringArray(configuration.trivy_scanners)
    && isStringArray(configuration.configured_sources)
    && isStringArray(configuration.inactive_bundled_packs);
  const rootValid = typeof payload.generated_from === "string"
    && typeof payload.counting_method === "string"
    && typeof payload.config_sha256 === "string"
    && (payload.rule_revision === null || typeof payload.rule_revision === "string");
  const rulesValid = payload.rules.every(isCatalogRule);

  if (!rootValid || !summaryValid || !configurationValid || !rulesValid) {
    throw new Error("The generated rule catalogue is incomplete or malformed. Regenerate it before starting the frontend.");
  }
  return payload as unknown as RuleCatalog;
}

function isCatalogRule(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const requiredStrings = ["key", "id", "title", "description", "severity", "category", "mode", "pack", "path"];
  const optionalStrings = ["confidence", "likelihood", "impact", "subcategory", "remediation"];
  return requiredStrings.every((field) => typeof value[field] === "string")
    && optionalStrings.every((field) => value[field] === undefined || typeof value[field] === "string")
    && isStringArray(value.languages)
    && isStringArray(value.cwe)
    && isStringArray(value.owasp)
    && (value.technologies === undefined || isStringArray(value.technologies))
    && (value.references === undefined || isStringArray(value.references))
    && (value.source === "community" || value.source === "custom")
    && typeof value.configured === "boolean"
    && isFiniteNumber(value.duplicate_count);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isNumberRecord(value: unknown): boolean {
  return isRecord(value) && Object.values(value).every(isFiniteNumber);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isElementVisible(element: HTMLElement): boolean {
  const style = window.getComputedStyle(element);
  return style.display !== "none" && style.visibility !== "hidden" && element.getClientRects().length > 0;
}

function formatList(values: string[]): string {
  if (values.length <= 1) return values[0] ?? "";
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(", ")}, and ${values[values.length - 1]}`;
}
