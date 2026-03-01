import Link from "next/link";
import { notFound } from "next/navigation";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ExternalLink, ArrowLeft } from "lucide-react";
import { ReportDetailTabs } from "@/components/reports/ReportDetailTabs";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

async function getReportDetails(id: string) {
  const base = API_BASE.replace(/\/$/, "");
  if (!base || !base.startsWith("http")) return null;

  const [reportRes, metaRes, configRes] = await Promise.all([
    fetch(`${base}/runs/${id}/report/report.json`, { cache: "force-cache" }),
    fetch(`${base}/runs/${id}/report/meta.json`, { cache: "force-cache" }),
    fetch(`${base}/runs/${id}/config.json`, { cache: "force-cache" }),
  ]);

  const report = reportRes.ok ? await reportRes.json() : null;
  const meta = metaRes.ok ? await metaRes.json() : null;
  const config = configRes.ok ? await configRes.json() : null;

  if (!report && !meta) return null;
  return { report, meta, config };
}

export function getReportHtmlUrl(id: string): string {
  const base = API_BASE.replace(/\/$/, "");
  if (!base || !base.startsWith("http")) return "";
  return `${base}/runs/${id}/report/report.html`;
}

function getAttackNarrativeProxyUrl(id: string): string {
  return `/api/reports/${id}/attack-narrative`;
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
  const attackNarrativeUrl = getAttackNarrativeProxyUrl(id);

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
          <Link
            href={`/dashboard/reports/${id}/full`}
            target="_blank"
            rel="noopener noreferrer"
          >
            View full report
            <ExternalLink className="size-4" />
          </Link>
        </Button>
      </div>

      <ReportDetailTabs
        reportId={id}
        summary={summary}
        vulnerabilities={vulnerabilities}
        reportHtmlUrl={reportHtmlUrl}
        attackNarrativeUrl={attackNarrativeUrl}
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
                    <span className="text-muted-foreground">
                      Pages captured:
                    </span>{" "}
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
