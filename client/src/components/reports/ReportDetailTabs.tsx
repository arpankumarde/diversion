"use client";

import { useState, useEffect, useRef } from "react";
import { ReportCharts } from "./ReportCharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetFooter,
} from "@/components/ui/sheet";
import {
  BarChart3,
  List,
  FileText,
  Swords,
  Loader2,
  BookOpen,
} from "lucide-react";
import { Streamdown } from "streamdown";
import Link from "next/link";
import Image from "next/image";

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;

function getCveIds(v: Record<string, unknown>): string[] {
  const fromField: string[] = [];
  if (v.cve_id != null) {
    fromField.push(String(v.cve_id).trim());
  }
  if (Array.isArray(v.cve_ids)) {
    fromField.push(...v.cve_ids.map((x) => String(x).trim()).filter(Boolean));
  } else if (v.cve_ids != null && typeof v.cve_ids === "string") {
    fromField.push(String(v.cve_ids).trim());
  }
  if (fromField.length > 0) return [...new Set(fromField)];

  const fromText: string[] = [];
  const text = [v.title, v.description].filter(Boolean).join(" ");
  const matches = text.match(CVE_REGEX);
  if (matches) fromText.push(...matches);
  return [...new Set(fromText)];
}

const severityColors: Record<
  string,
  "destructive" | "default" | "secondary" | "outline"
> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
  info: "outline",
};

type TabId = "overview" | "vulnerabilities" | "attack-narrative" | "report";

const tabs: {
  id: TabId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  { id: "overview", label: "Overview", icon: BarChart3 },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: List },
  { id: "attack-narrative", label: "Attack Narrative", icon: Swords },
  // { id: "report", label: "Full Report", icon: FileText },
];

const CLAUDE_URL = "https://claude.ai"; // placeholder - add actual link later
const CHATGPT_URL = "https://chat.openai.com"; // placeholder - add actual link later

export function ReportDetailTabs({
  reportId,
  summary,
  vulnerabilities,
  reportHtmlUrl,
  attackNarrativeUrl,
}: {
  reportId: string;
  summary: Record<string, number> | null;
  vulnerabilities: Record<string, unknown>[];
  reportHtmlUrl: string;
  attackNarrativeUrl: string;
}) {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [narrativeState, setNarrativeState] = useState<
    "idle" | "loading" | "found" | "not-found" | "generating" | "error"
  >("idle");
  const [narrativeContent, setNarrativeContent] = useState<string>("");
  const [retryKey, setRetryKey] = useState(0);

  const [learnMoreOpen, setLearnMoreOpen] = useState(false);
  const [learnMoreVuln, setLearnMoreVuln] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [explainState, setExplainState] = useState<
    "idle" | "loading" | "done" | "error"
  >("idle");
  const [explanation, setExplanation] = useState<string>("");

  useEffect(() => {
    if (activeTab !== "attack-narrative" || !attackNarrativeUrl) return;
    let cancelled = false;
    const controller = new AbortController();
    const FETCH_TIMEOUT_MS = 30_000;

    const doFetch = () => {
      queueMicrotask(() => setNarrativeState("loading"));
      const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      fetch(attackNarrativeUrl, { signal: controller.signal })
        .then((res) => {
          if (cancelled) return;
          clearTimeout(timeoutId);
          if (res.status === 202) {
            setNarrativeState("generating");
            return;
          }
          if (res.status === 404) {
            setNarrativeState("not-found");
            return;
          }
          if (res.status >= 500 || res.status === 503) {
            setNarrativeState("error");
            return;
          }
          if (!res.ok) throw new Error("Failed to fetch");
          return res.text();
        })
        .then((text) => {
          if (cancelled) return;
          if (text !== undefined) {
            setNarrativeContent(text);
            setNarrativeState("found");
          }
        })
        .catch(() => {
          if (!cancelled) setNarrativeState("error");
        });
    };

    doFetch();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [activeTab, attackNarrativeUrl, retryKey]);

  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (
      narrativeState !== "generating" ||
      activeTab !== "attack-narrative" ||
      !attackNarrativeUrl
    ) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      return;
    }
    pollIntervalRef.current = setInterval(() => {
      fetch(attackNarrativeUrl)
        .then((res) => {
          if (res.status === 200) {
            return res.text().then((text) => {
              setNarrativeContent(text);
              setNarrativeState("found");
            });
          }
          if (res.status >= 500 || res.status === 503) {
            setNarrativeState("error");
          }
        })
        .catch(() => setNarrativeState("error"));
    }, 15_000);
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [narrativeState, activeTab, attackNarrativeUrl]);

  useEffect(() => {
    if (!learnMoreOpen || !learnMoreVuln || !reportId) return;
    const controller = new AbortController();
    let cancelled = false;
    fetch(`/api/reports/${reportId}/explain-vulnerability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(learnMoreVuln),
      signal: controller.signal,
    })
      .then(async (res) => {
        if (!res.ok) throw new Error("Failed to explain");
        const reader = res.body?.getReader();
        if (!reader) throw new Error("No response body");
        const decoder = new TextDecoder();
        let text = "";
        while (true) {
          const { done, value } = await reader.read();
          if (cancelled) break;
          if (done) break;
          text += decoder.decode(value, { stream: true });
          setExplanation(text);
        }
        if (!cancelled) setExplainState("done");
      })
      .catch(() => {
        if (!cancelled) setExplainState("error");
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [learnMoreOpen, learnMoreVuln, reportId]);

  const openLearnMore = (v: Record<string, unknown>) => {
    setExplainState("loading");
    setExplanation("");
    setLearnMoreVuln(v);
    setLearnMoreOpen(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2 border-b pb-2">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === id
                ? "bg-primary text-primary-foreground"
                : "bg-muted hover:bg-muted/80"
            }`}
          >
            <Icon className="size-4" />
            {label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="space-y-6">
          {summary && (
            <div className="flex flex-wrap gap-2">
              <Badge variant="destructive">
                Critical: {summary.critical ?? 0}
              </Badge>
              <Badge variant="destructive">High: {summary.high ?? 0}</Badge>
              <Badge variant="default">Medium: {summary.medium ?? 0}</Badge>
              <Badge variant="secondary">Low: {summary.low ?? 0}</Badge>
              <Badge variant="outline">Info: {summary.info ?? 0}</Badge>
              <Badge variant="outline">
                Total: {summary.total_hypotheses ?? 0}
              </Badge>
              <Badge variant="outline">
                Confirmed: {summary.confirmed_vulnerabilities ?? 0}
              </Badge>
            </div>
          )}
          {vulnerabilities.length > 0 && (
            <ReportCharts vulnerabilities={vulnerabilities} />
          )}
        </div>
      )}

      {activeTab === "vulnerabilities" && (
        <div className="space-y-4">
          {vulnerabilities.map((v: Record<string, unknown>, i: number) => {
            const cveIds = getCveIds(v);
            const cweId = v.cwe_id != null ? String(v.cwe_id) : null;
            return (
              <div
                key={String(v.id ?? i)}
                className="relative rounded-lg border p-4"
              >
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute top-3 right-3"
                  onClick={() => openLearnMore(v)}
                >
                  <BookOpen className="size-4" />
                  Learn more
                </Button>
                <div className="flex flex-wrap items-center gap-2 pr-32">
                  <span className="font-mono text-xs text-muted-foreground">
                    {String(v.id ?? "")}
                  </span>
                  <Badge
                    variant={
                      severityColors[String(v.severity ?? "")] || "secondary"
                    }
                  >
                    {String(v.severity ?? "")}
                  </Badge>
                  {v.vuln_type != null && (
                    <Badge variant="outline">{String(v.vuln_type)}</Badge>
                  )}
                  {cweId && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-xs"
                    >
                      <Badge variant="outline" className="hover:bg-muted">
                        {cweId}
                      </Badge>
                    </a>
                  )}
                  {cveIds.length > 0 &&
                    cveIds.map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs"
                      >
                        <Badge variant="outline" className="hover:bg-muted">
                          {cve}
                        </Badge>
                      </a>
                    ))}
                </div>
                <h3 className="mt-2 font-medium">{String(v.title ?? "")}</h3>
                {v.description != null && (
                  <p className="mt-1 text-sm text-muted-foreground">
                    {String(v.description)}
                  </p>
                )}
                {v.endpoint != null && (
                  <p className="mt-1 font-mono text-xs text-muted-foreground">
                    {String(v.endpoint)}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {activeTab === "attack-narrative" && (
        <div className="space-y-4">
          {!attackNarrativeUrl && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Attack narrative is not available for this report.
            </p>
          )}
          {attackNarrativeUrl &&
            (narrativeState === "loading" ||
              narrativeState === "generating") && (
              <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed bg-muted/30 py-12">
                <Loader2 className="size-6 animate-spin text-muted-foreground" />
                <div className="text-center space-y-1">
                  <p className="text-sm font-medium">
                    {narrativeState === "generating"
                      ? "Generating attack narrative…"
                      : "Loading attack narrative…"}
                  </p>
                  <p className="text-xs text-muted-foreground max-w-sm">
                    {narrativeState === "generating"
                      ? "This may take several minutes. The page will auto-refresh when ready."
                      : "Please wait."}
                  </p>
                </div>
              </div>
            )}
          {attackNarrativeUrl && narrativeState === "not-found" && (
            <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed bg-muted/30 py-12">
              <p className="text-sm text-muted-foreground">
                No attack narrative yet.
              </p>
              <Button variant="outline">Generate attack narrative</Button>
            </div>
          )}
          {attackNarrativeUrl && narrativeState === "error" && (
            <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed bg-muted/30 py-12">
              <p className="text-sm text-muted-foreground text-center max-w-sm">
                The request timed out or failed. Generation may still be in
                progress—try again in a few minutes.
              </p>
              <Button
                variant="outline"
                onClick={() => setRetryKey((k) => k + 1)}
              >
                Try again
              </Button>
            </div>
          )}
          {attackNarrativeUrl && narrativeState === "found" && (
            <div className="prose prose-sm dark:prose-invert w-[78dvw] rounded-lg border bg-muted/30 p-6">
              <Streamdown>{narrativeContent}</Streamdown>
            </div>
          )}
        </div>
      )}

      {activeTab === "report" && (
        <div className="overflow-hidden rounded-lg border bg-muted/30">
          <iframe
            src={reportHtmlUrl}
            title="Full security report"
            className="h-[70vh] w-full min-h-[500px] bg-white"
            sandbox="allow-scripts allow-same-origin"
            style={{ colorScheme: "light" }}
          />
        </div>
      )}

      <Sheet open={learnMoreOpen} onOpenChange={setLearnMoreOpen}>
        <SheetContent
          side="right"
          className="flex w-full max-w-lg flex-col sm:max-w-xl px-4"
        >
          <SheetHeader className="px-0">
            <SheetTitle>
              {learnMoreVuln
                ? String(learnMoreVuln.title ?? "Vulnerability")
                : "Learn more"}
            </SheetTitle>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto px-1 py-4">
            {explainState === "loading" && !explanation && (
              <div className="flex flex-col items-center justify-center gap-4 py-12">
                <Loader2 className="size-8 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">Explaining…</p>
              </div>
            )}
            {explanation && (
              <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                <Streamdown>{explanation}</Streamdown>
                {explainState === "loading" && (
                  <span className="inline-block w-2 h-4 ml-0.5 animate-pulse bg-current align-middle" />
                )}
              </div>
            )}
            {explainState === "error" && (
              <p className="text-sm text-destructive">
                Failed to generate explanation. Please try again.
              </p>
            )}
          </div>
          <SheetFooter className="flex flex-row flex-wrap gap-2 border-t pt-4">
            <Button variant="outline" size="sm" asChild>
              <Link
                href={`${CLAUDE_URL}/new?q=${encodeURIComponent(`Explain this security vulnerability as if to a product manager: ${learnMoreVuln?.title} ${learnMoreVuln?.description}`)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Image
                  src="https://models.dev/logos/anthropic.svg"
                  alt="Claude"
                  className="size-4 invert"
                  width={16}
                  height={16}
                />
                Open in Claude
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link
                href={`${CHATGPT_URL}/?hints=search&q=${encodeURIComponent(`Explain this security vulnerability as if to a product manager: ${learnMoreVuln?.title} ${learnMoreVuln?.description}`)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Image
                  src="https://models.dev/logos/openai.svg"
                  alt="ChatGPT"
                  className="size-4 invert"
                  width={16}
                  height={16}
                />
                Open in ChatGPT
              </Link>
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
