import Link from "next/link";
import { notFound } from "next/navigation";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ExternalLink, ArrowLeft } from "lucide-react";
import { ReportDetailTabs } from "@/components/reports/ReportDetailTabs";

async function getReportDetails(id: string) {
  const base =
    process.env.APP_BASE_URL ||
    process.env.NEXT_PUBLIC_APP_BASE_URL ||
    "http://localhost:3000";
  const res = await fetch(`${base}/api/reports/${id}`, { cache: "no-store" });
  if (!res.ok) return null;
  return res.json();
}

function getReportHtmlUrl(id: string): string {
  const reportsBase = process.env.NEXT_PUBLIC_REPORTS_BASE_URL;
  const appBase =
    process.env.APP_BASE_URL ||
    process.env.NEXT_PUBLIC_APP_BASE_URL ||
    "http://localhost:3000";

  if (reportsBase && reportsBase.startsWith("http")) {
    return `${reportsBase.replace(/\/$/, "")}/${id}/report/report.html`;
  }
  return `${appBase.replace(/\/$/, "")}/api/reports-static/${id}/report/report.html`;
}

export default async function ReportDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = await getReportDetails(id);

  if (!data) notFound();

  const { report, meta, config } = data;
  const reportHtmlUrl = getReportHtmlUrl(id);

  const metadata = report?.metadata || meta;
  const summary = report?.summary;
  const vulnerabilities = report?.vulnerabilities || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <Link
            href="/dashboard/reports"
            className="mb-2 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            Back to reports
          </Link>
          <h1 className="text-2xl font-semibold font-mono">{id}</h1>
          {metadata?.target_url && (
            <p className="mt-1 text-sm text-muted-foreground">
              Target: {metadata.target_url}
            </p>
          )}
        </div>
        <Button asChild size="lg">
          <a href={reportHtmlUrl} target="_blank" rel="noopener noreferrer">
            View full report
            <ExternalLink className="size-4" />
          </a>
        </Button>
      </div>

      <ReportDetailTabs
        summary={summary}
        vulnerabilities={vulnerabilities}
        reportHtmlUrl={reportHtmlUrl}
      />

      {(meta || config) && (
        <div className="grid gap-4 md:grid-cols-2">
          {meta && (
            <Card>
              <CardHeader>
                <CardTitle>Run metadata</CardTitle>
                <CardDescription>Execution details</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                {meta.generated_at && (
                  <p>
                    <span className="text-muted-foreground">Generated:</span>{" "}
                    {meta.generated_at}
                  </p>
                )}
                {meta.total_elapsed_seconds != null && (
                  <p>
                    <span className="text-muted-foreground">Duration:</span>{" "}
                    {Math.round(meta.total_elapsed_seconds)}s
                  </p>
                )}
                {meta.llm_usage && (
                  <p>
                    <span className="text-muted-foreground">LLM cost:</span> $
                    {meta.llm_usage.total_cost_usd?.toFixed(4)}
                  </p>
                )}
                {meta.network && (
                  <p>
                    <span className="text-muted-foreground">Pages captured:</span>{" "}
                    {meta.network.recon_pages_captured}
                  </p>
                )}
              </CardContent>
            </Card>
          )}
          {config && (
            <Card>
              <CardHeader>
                <CardTitle>Config</CardTitle>
                <CardDescription>Scan configuration</CardDescription>
              </CardHeader>
              <CardContent>
                <pre className="max-h-48 overflow-auto rounded bg-muted p-4 text-xs">
                  {JSON.stringify(config, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
