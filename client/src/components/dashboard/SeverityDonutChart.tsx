"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
} from "recharts";
import { ChartContainer, ChartTooltipContent } from "@/components/ui/chart";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", // bright red
  high: "#f59e42", // orange
  medium: "#3b82f6", // yellow
  low: "#22c55e", // green
  info: "#facc15", // blue
};

export type SeverityData = { name: string; value: number }[];

export function SeverityDonutChart({ data }: { data: SeverityData }) {
  if (data.length === 0) {
    return (
      <div className="flex h-[280px] items-center justify-center rounded-lg border border-dashed bg-muted/30 text-muted-foreground">
        No severity data to display
      </div>
    );
  }

  const config = Object.fromEntries(
    data.map((d) => [
      d.name,
      {
        label: d.name.charAt(0).toUpperCase() + d.name.slice(1),
        color: SEVERITY_COLORS[d.name] || "#64748b",
      },
    ]),
  );

  return (
    <ChartContainer config={config} className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={2}
            label={({ name, value, percent }) =>
              value > 0 ? `${name} (${value})` : null
            }
          >
            {data.map((entry, i) => (
              <Cell
                key={entry.name}
                fill={SEVERITY_COLORS[entry.name] || "#64748b"}
              />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltipContent hideLabel />} />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}
