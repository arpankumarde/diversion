"use client";

import { useSearchParams } from "next/navigation";
import Link from "next/link";

function getReportHtmlUrl(id: string, reportsBaseUrl?: string | null): string {
  if (typeof window === "undefined") return "";
  if (reportsBaseUrl && reportsBaseUrl.startsWith("http")) {
    return `${reportsBaseUrl.replace(/\/$/, "")}/${id}/report/report.html`;
  }
  return `${window.location.origin}/api/reports-static/${id}/report/report.html`;
}

export function ReportViewer({
  reportId,
  reportIds,
  reportsBaseUrl,
}: {
  reportId: string | null;
  reportIds: string[];
  reportsBaseUrl?: string | null;
}) {
  const searchParams = useSearchParams();
  const selected = reportId ?? searchParams.get("selected");

  if (reportIds.length === 0) return null;

  const displayId = selected || reportIds[0];
  const reportUrl = getReportHtmlUrl(displayId, reportsBaseUrl);

  return (
    <div className="mt-6 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-muted-foreground">
          View report:
        </span>
        {reportIds.map((id) => (
          <Link
            key={id}
            href={`/dashboard/reports?selected=${id}`}
            className={`rounded-md px-3 py-1.5 text-sm font-mono transition-colors ${
              id === displayId
                ? "bg-primary text-primary-foreground"
                : "bg-muted hover:bg-muted/80"
            }`}
          >
            {id}
          </Link>
        ))}
      </div>
      <div className="overflow-hidden rounded-lg border bg-muted/30">
        <iframe
          src={reportUrl}
          title="Security report"
          className="h-[70vh] w-full min-h-[500px]"
          sandbox="allow-scripts allow-same-origin"
        />
      </div>
    </div>
  );
}
