"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { FileText, ChevronRight } from "lucide-react";
import { getAuditLogs, type AuditLog } from "@/lib/audit-logs";

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function formatReportId(runId: string): string {
  const match = runId.match(/^([a-f0-9]+)_(\d{8})_(\d{6})$/);
  return match ? match[1] || runId : runId;
}

export function AuditTrailsTable() {
  const [trails, setTrails] = useState<AuditLog[]>([]);

  useEffect(() => {
    setTrails(getAuditLogs());
    const handleStorage = () => setTrails(getAuditLogs());
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>View history</CardTitle>
        <CardDescription>
          Last 20 full report access events (stored locally)
        </CardDescription>
      </CardHeader>
      <CardContent>
        {trails.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No audit logs yet. Grant access to a full report to see entries here.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="pb-3 pr-4 font-medium">User</th>
                  <th className="pb-3 pr-4 font-medium">Report</th>
                  <th className="pb-3 font-medium">Viewed at</th>
                </tr>
              </thead>
              <tbody>
                {trails.map(({ user, reportId, viewedAt }, index) => (
                  <tr key={index} className="border-b last:border-0">
                    <td className="py-3 pr-4 font-mono text-xs">{user}</td>
                    <td className="py-3 pr-4">
                      <Link
                        href={`/dashboard/reports/${reportId}/full`}
                        className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                      >
                        <FileText className="size-3.5" />
                        {formatReportId(reportId)}
                        <ChevronRight className="size-3.5" />
                      </Link>
                    </td>
                    <td className="py-3 text-muted-foreground">
                      {formatDate(viewedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
