"use client";

import { useMemo } from "react";
import { hierarchy, pack } from "d3-hierarchy";
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

type PackedNode = { x: number; y: number; r: number; data: { name: string; value: number } };

function PackedBubbleChart({
  data,
  colors,
  width,
  height,
}: {
  data: { name: string; value: number }[];
  colors: string[];
  width: number;
  height: number;
}) {
  const nodes = useMemo(() => {
    if (data.length === 0) return [];
    type DataNode = { name: string; value: number };
    const getValue = (d: unknown): number =>
      typeof d === "object" && d !== null && "value" in d && typeof (d as DataNode).value === "number"
        ? (d as DataNode).value
        : 0;
    const root = hierarchy<{ children: DataNode[] }>({ children: data })
      .sum(getValue)
      .sort((a, b) => (b.value ?? 0) - (a.value ?? 0));
    pack<{ children: DataNode[] }>()
      .size([width, height])
      .padding(4)(root);
    return root.leaves() as unknown as PackedNode[];
  }, [data, width, height]);

  if (nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        No data
      </div>
    );
  }

  const padding = 8;

  return (
    <svg
      viewBox={`${-padding} ${-padding} ${width + padding * 2} ${height + padding * 2}`}
      className="h-full w-full text-foreground"
      preserveAspectRatio="xMidYMid meet"
    >
      {nodes.map((node, i) => (
        <g key={node.data.name} transform={`translate(${node.x},${node.y})`}>
          <circle
            r={node.r}
            fill={colors[i % colors.length]}
            fillOpacity={0.85}
            stroke="white"
            strokeWidth={1.5}
          />
          <text
            textAnchor="middle"
            dominantBaseline="middle"
            fill="currentColor"
            className="text-sm font-medium"
            style={{
              fontSize: Math.max(10, Math.min(14, node.r * 0.6)),
            }}
          >
            {node.data.name}
          </text>
        </g>
      ))}
    </svg>
  );
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
        <div className="h-full w-full min-h-[200px]">
          <PackedBubbleChart
            data={byType}
            colors={PIE_COLORS}
            width={400}
            height={260}
          />
        </div>
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
