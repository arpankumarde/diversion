"use client";

import { useState } from "react";
import { ReportCharts } from "./ReportCharts";
import { Badge } from "@/components/ui/badge";
import { BarChart3, List, FileText } from "lucide-react";

const severityColors: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
  info: "outline",
};

type TabId = "overview" | "vulnerabilities" | "report";

const tabs: { id: TabId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "overview", label: "Overview", icon: BarChart3 },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: List },
  { id: "report", label: "Full Report", icon: FileText },
];

export function ReportDetailTabs({
  summary,
  vulnerabilities,
  reportHtmlUrl,
}: {
  summary: Record<string, number> | null;
  vulnerabilities: Record<string, unknown>[];
  reportHtmlUrl: string;
}) {
  const [activeTab, setActiveTab] = useState<TabId>("overview");

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
              <Badge variant="destructive">Critical: {summary.critical ?? 0}</Badge>
              <Badge variant="destructive">High: {summary.high ?? 0}</Badge>
              <Badge variant="default">Medium: {summary.medium ?? 0}</Badge>
              <Badge variant="secondary">Low: {summary.low ?? 0}</Badge>
              <Badge variant="outline">Info: {summary.info ?? 0}</Badge>
              <Badge variant="outline">Total: {summary.total_hypotheses ?? 0}</Badge>
              <Badge variant="outline">Confirmed: {summary.confirmed_vulnerabilities ?? 0}</Badge>
            </div>
          )}
          {vulnerabilities.length > 0 && (
            <ReportCharts vulnerabilities={vulnerabilities} />
          )}
        </div>
      )}

      {activeTab === "vulnerabilities" && (
        <div className="space-y-4">
          {vulnerabilities.map((v: Record<string, unknown>, i: number) => (
            <div
              key={String(v.id ?? i)}
              className="rounded-lg border p-4"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">
                  {String(v.id ?? "")}
                </span>
                <Badge
                  variant={severityColors[String(v.severity ?? "")] || "secondary"}
                >
                  {String(v.severity ?? "")}
                </Badge>
                {v.vuln_type != null && (
                  <Badge variant="outline">{String(v.vuln_type)}</Badge>
                )}
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
          ))}
        </div>
      )}

      {activeTab === "report" && (
        <div className="overflow-hidden rounded-lg border bg-muted/30">
          <iframe
            src={reportHtmlUrl}
            title="Full security report"
            className="h-[70vh] w-full min-h-[500px]"
            sandbox="allow-scripts allow-same-origin"
          />
        </div>
      )}
    </div>
  );
}
