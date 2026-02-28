"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { ChartContainer, ChartTooltipContent } from "@/components/ui/chart";

type VulnItem = { vuln_type?: string; severity?: string };

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#65a30d",
  info: "#64748b",
};

const PIE_COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#3b82f6",
  "#8b5cf6",
  "#ec4899",
  "#06b6d4",
  "#84cc16",
  "#f43f5e",
];

function aggregateByKey(items: VulnItem[], key: "vuln_type" | "severity") {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const val = String(item[key] || "Unknown");
    counts[val] = (counts[val] || 0) + 1;
  }
  return Object.entries(counts).map(([name, value]) => ({ name, value }));
}

export function ReportCharts({ vulnerabilities }: { vulnerabilities: VulnItem[] }) {
  const byType = aggregateByKey(vulnerabilities, "vuln_type");
  const bySeverity = aggregateByKey(vulnerabilities, "severity");

  const typeConfig = Object.fromEntries(
    byType.map((d, i) => [d.name, { label: d.name, color: PIE_COLORS[i % PIE_COLORS.length] }])
  );
  const severityConfig = Object.fromEntries(
    bySeverity.map((d) => [d.name, { label: d.name, color: SEVERITY_COLORS[d.name] || "#64748b" }])
  );

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <ChartContainer
        config={typeConfig}
        className="h-[280px] w-full"
      >
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={byType}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={100}
              paddingAngle={2}
              label={({ name, percent }) =>
                `${name} (${(percent * 100).toFixed(0)}%)`
              }
            >
              {byType.map((_, i) => (
                <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltipContent hideLabel />} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </ChartContainer>

      <ChartContainer
        config={severityConfig}
        className="h-[280px] w-full"
      >
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={bySeverity}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={100}
              paddingAngle={2}
              label={({ name, percent }) =>
                `${name} (${(percent * 100).toFixed(0)}%)`
              }
            >
              {bySeverity.map((entry, i) => (
                <Cell
                  key={i}
                  fill={SEVERITY_COLORS[entry.name] || PIE_COLORS[i]}
                />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltipContent hideLabel />} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </ChartContainer>
    </div>
  );
}
