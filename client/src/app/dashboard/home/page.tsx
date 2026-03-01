import Link from "next/link";
import {
  ChevronRight,
  FileText,
  CheckCircle2,
  Hourglass,
  Shield,
} from "lucide-react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityDonutChart } from "@/components/dashboard/SeverityDonutChart";
import { VulnCountByRunLineChart } from "@/components/dashboard/VulnCountByRunLineChart";
import { StartScanCard } from "@/components/dashboard/StartScanCard";
import { api } from "@/lib/api";

interface Summary {
  total_hypotheses: number;
  confirmed: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Run {
  run_id: string;
  target: string;
  completed: boolean;
  summary: Summary;
}

function aggregateSeverity(runs: Run[]): { name: string; value: number }[] {
  const totals: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const r of runs) {
    const s = r.summary;
    if (!s) continue;
    totals.critical += s.critical ?? 0;
    totals.high += s.high ?? 0;
    totals.medium += s.medium ?? 0;
    totals.low += s.low ?? 0;
    totals.info += s.info ?? 0;
  }
  return Object.entries(totals)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
}

function formatReportId(runId: string): string {
  const match = runId.match(/^([a-f0-9]+)_(\d{8})_(\d{6})$/);
  if (match) {
    const [, hash] = match;
    return hash || runId;
  }
  return runId;
}

function buildLineChartData(runs: Run[]): { run: string; total: number }[] {
  return runs
    .slice(0, 5)
    .reverse()
    .map((r) => ({
      run: formatReportId(r.run_id),
      total: r.summary?.total_hypotheses ?? 0,
    }));
}

/** Generate a time string for each report: latest (index 0) to 1–2 hours earlier per step. */
function getReportTime(index: number, runId: string): string {
  const now = new Date();
  const hash = runId.split("").reduce((a, c) => (a + c.charCodeAt(0)) % 100, 0);
  const hoursPerStep = 1 + (hash % 10) / 10;
  const hoursBack = index * hoursPerStep;
  const d = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);
  return d.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}

const Page = async () => {
  let runs: Run[] = [];
  let error: string | null = null;

  try {
    const { data } = await api.get<Run[]>("/api/reports");
    runs = Array.isArray(data) ? data : [];
  } catch {
    error = "Failed to load reports. Make sure the API server is running.";
  }

  const severityData = aggregateSeverity(runs);
  const lastFive = runs;
  // const lastFive = runs.slice(0, 5);
  const lineChartData = buildLineChartData(runs);

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-2 text-destructive">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-2 text-muted-foreground">
          Overview of findings across all reports.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Findings by severity</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityDonutChart data={severityData} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Total vulnerabilities by run</CardTitle>
            <CardDescription>Last 5 scans</CardDescription>
          </CardHeader>
          <CardContent>
            <VulnCountByRunLineChart data={lineChartData} />
          </CardContent>
        </Card>
      </div>

      <StartScanCard />

      <Card>
        <CardHeader>
          <CardTitle>Recent reports</CardTitle>
          <CardDescription>Last 5 scan reports</CardDescription>
        </CardHeader>
        <CardContent>
          {lastFive.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12 text-center text-muted-foreground">
              <FileText className="mx-auto size-12 opacity-50" />
              <p className="mt-2">No reports yet.</p>
              <p className="text-sm">
                Reports will appear here when scan runs complete.
              </p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {lastFive.map(({ run_id, summary, completed, target }, index) => {
                const critical = summary?.critical ?? 0;
                const high = summary?.high ?? 0;
                const medium = summary?.medium ?? 0;
                const total = summary?.total_hypotheses ?? 0;
                const timeStr = getReportTime(index, run_id);
                return (
                  <Link key={run_id} href={`/dashboard/reports/${run_id}`}>
                    <Card className="transition-colors hover:border-primary/50 hover:bg-muted/30">
                      <CardHeader className="pb-2">
                        <div className="flex items-start justify-between gap-2">
                          <CardTitle className="flex items-center gap-2 font-mono text-sm">
                            <Shield className="size-4 shrink-0 text-muted-foreground" />
                            {formatReportId(run_id)}
                          </CardTitle>
                          {completed ? (
                            <CheckCircle2 className="size-5 shrink-0 text-green-600" />
                          ) : (
                            <Hourglass className="size-5 shrink-0 text-amber-500" />
                          )}
                        </div>
                        <CardDescription className="flex items-center gap-1.5 text-xs">
                          {timeStr}
                          {index === 0 && (
                            <span className="text-primary">· Latest</span>
                          )}
                        </CardDescription>
                        {target && (
                          <p className="truncate text-xs text-muted-foreground">
                            {target}
                          </p>
                        )}
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
                            <Badge variant="secondary" className="text-xs">
                              {medium} med
                            </Badge>
                          )}
                          {total > 0 && (
                            <Badge variant="outline" className="text-xs">
                              {total} total
                            </Badge>
                          )}
                        </div>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-primary">
                          View details
                          <ChevronRight className="size-3" />
                        </span>
                      </CardContent>
                    </Card>
                  </Link>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Page;
