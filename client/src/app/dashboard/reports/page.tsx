import Link from "next/link";
import { Suspense } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileText, ChevronRight, Shield } from "lucide-react";
import { ReportViewer } from "@/components/reports/ReportViewer";

async function getReports(): Promise<
  { id: string; summary: { critical?: number; high?: number; medium?: number; low?: number; info?: number; total_hypotheses?: number } | null }[]
> {
  const base =
    process.env.APP_BASE_URL ||
    process.env.NEXT_PUBLIC_APP_BASE_URL ||
    "http://localhost:3000";
  const res = await fetch(`${base}/api/reports?summary=1`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch reports");
  const data = await res.json();
  const reports = data.reports ?? [];
  return Array.isArray(reports) ? reports : [];
}

function formatReportId(id: string): { date?: string; hash?: string } {
  const match = id.match(/^([a-f0-9]+)_(\d{8})_(\d{6})$/);
  if (match) {
    const [, hash, datePart, timePart] = match;
    const date = `${datePart.slice(0, 4)}-${datePart.slice(4, 6)}-${datePart.slice(6, 8)}`;
    const time = `${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}`;
    return { hash, date: `${date} ${time}` };
  }
  return { hash: id };
}

function SummaryBadges({
  summary,
}: {
  summary: { critical?: number; high?: number; medium?: number; total_hypotheses?: number } | null;
}) {
  if (!summary) return null;
  const total = summary.total_hypotheses ?? 0;
  const critical = summary.critical ?? 0;
  const high = summary.high ?? 0;
  const medium = summary.medium ?? 0;
  if (total === 0) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {critical > 0 && (
        <Badge variant="destructive" className="text-xs">
          {critical} critical
        </Badge>
      )}
      {high > 0 && (
        <Badge variant="destructive" className="text-xs">
          {high} high
        </Badge>
      )}
      {medium > 0 && (
        <Badge variant="default" className="text-xs">
          {medium} med
        </Badge>
      )}
      <Badge variant="outline" className="text-xs">
        {total} total
      </Badge>
    </div>
  );
}

export default async function ReportsPage({
  searchParams,
}: {
  searchParams: Promise<{ selected?: string }>;
}) {
  let reports: { id: string; summary: Record<string, number> | null }[] = [];
  let error: string | null = null;

  try {
    reports = await getReports();
  } catch {
    error = "Failed to load reports. Make sure the reports server is running.";
  }

  const { selected } = await searchParams;

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Reports</h1>
        <p className="mt-2 text-destructive">{error}</p>
      </div>
    );
  }

  const reportIds = reports.map((r) => r.id);

  return (
    <div>
      <h1 className="text-2xl font-semibold">Reports</h1>
      <p className="mt-2 text-muted-foreground">
        Security scan reports from NAZITEST runs. Select a report to view details
        and the full HTML report.
      </p>

      {reports.length === 0 ? (
        <div className="mt-8 rounded-lg border border-dashed p-8 text-center text-muted-foreground">
          <FileText className="mx-auto size-12 opacity-50" />
          <p className="mt-2">No reports yet.</p>
          <p className="text-sm">
            Reports will appear here when scan runs complete.
          </p>
        </div>
      ) : (
        <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {reports.map(({ id, summary }) => {
              const { date, hash } = formatReportId(id);
              return (
                <Card
                  key={id}
                  size="sm"
                  className={
                    selected === id
                      ? "ring-2 ring-primary"
                      : ""
                  }
                >
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 font-mono text-sm">
                      <Shield className="size-4 text-muted-foreground" />
                      {hash || id}
                    </CardTitle>
                    {date && (
                      <CardDescription>{date}</CardDescription>
                    )}
                    <SummaryBadges summary={summary} />
                  </CardHeader>
                  <CardContent>
                    <div className="flex gap-2">
                      <Button asChild variant="outline" size="sm" className="flex-1">
                        <Link href={`/dashboard/reports?selected=${id}`}>
                          Preview
                          <ChevronRight className="size-4" />
                        </Link>
                      </Button>
                      <Button asChild size="sm" className="flex-1">
                        <Link href={`/dashboard/reports/${id}`}>
                          Details
                        </Link>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <Suspense fallback={<div className="mt-6 h-[70vh] animate-pulse rounded-lg border bg-muted/30" />}>
            <ReportViewer
              reportId={selected ?? null}
              reportIds={reportIds}
              reportsBaseUrl={process.env.NEXT_PUBLIC_REPORTS_BASE_URL}
            />
          </Suspense>
        </>
      )}
    </div>
  );
}
