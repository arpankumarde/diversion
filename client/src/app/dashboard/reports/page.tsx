import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  FileText,
  ChevronRight,
  Shield,
  CheckCircle2,
  Hourglass,
  ExternalLink,
} from "lucide-react";
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

interface Run {
  run_id: string;
  target: string;
  completed: boolean;
  summary: Summary;
}

function formatReportId(runId: string): { date?: string; hash?: string } {
  const match = runId.match(/^([a-f0-9]+)_(\d{8})_(\d{6})$/);
  if (match) {
    const [, hash, datePart, timePart] = match;
    const date = `${datePart.slice(0, 4)}-${datePart.slice(4, 6)}-${datePart.slice(6, 8)}`;
    const time = `${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}`;
    return { hash, date: `${date} ${time}` };
  }
  return { hash: runId };
}

function SummaryBadges({ summary }: { summary: Summary | null }) {
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

export default async function ReportsPage() {
  let runs: Run[] = [];
  let error: string | null = null;

  try {
    const { data } = await api.get<Run[]>("/api/reports");
    runs = Array.isArray(data) ? data : [];
  } catch {
    error = "Failed to load reports. Make sure the API server is running.";
  }

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Reports</h1>
        <p className="mt-2 text-destructive">{error}</p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold">Reports</h1>
      <p className="mt-2 text-muted-foreground">
        Security scan reports from NAZITEST runs. Select a report to view
        details and the full HTML report.
      </p>

      {runs.length === 0 ? (
        <div className="mt-8 rounded-lg border border-dashed p-8 text-center text-muted-foreground">
          <FileText className="mx-auto size-12 opacity-50" />
          <p className="mt-2">No reports yet.</p>
          <p className="text-sm">
            Reports will appear here when scan runs complete.
          </p>
        </div>
      ) : (
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {runs.map(({ run_id, summary, target, completed }) => {
            const { date, hash } = formatReportId(run_id);
            return (
              <Card key={run_id} size="sm">
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="flex items-center gap-2 font-mono text-sm">
                      <Shield className="size-4 text-muted-foreground" />
                      {hash || run_id}
                    </CardTitle>
                    {completed ? (
                      <CheckCircle2 className="size-5 shrink-0 text-green-600" />
                    ) : (
                      <Hourglass className="size-5 shrink-0 text-amber-500" />
                    )}
                  </div>
                  {date && <CardDescription>{date}</CardDescription>}
                  {target && (
                    <p className="truncate text-xs text-muted-foreground">
                      {target}
                    </p>
                  )}
                  <SummaryBadges summary={summary} />
                </CardHeader>
                <CardContent>
                  <div className="flex gap-2 pt-2">
                    <Button
                      asChild
                      variant="outline"
                      size="sm"
                      className="flex-1"
                    >
                      <Link href={`/dashboard/reports/${run_id}`}>
                        View details <ChevronRight className="size-4" />
                      </Link>
                    </Button>
                    <Button asChild size="sm" className="flex-1">
                      <Link
                        target="_blank"
                        href={`/dashboard/reports/${run_id}/full`}
                      >
                        View report <ExternalLink className="size-4" />
                      </Link>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
