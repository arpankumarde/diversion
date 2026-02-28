import { NextRequest, NextResponse } from "next/server";
import { readdir, readFile } from "fs/promises";
import path from "path";

const REPORTS_SOURCE = process.env.REPORTS_SOURCE || "local";
const REPORTS_API_URL = process.env.REPORTS_API_URL || "";
const NAZITEST_RUNS_PATH = path.join(process.cwd(), "..", "nazitest_runs");

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const withSummary = searchParams.get("summary") === "1";

    if (REPORTS_SOURCE === "remote" && REPORTS_API_URL) {
      const res = await fetch(`${REPORTS_API_URL}/reports`);
      if (!res.ok) throw new Error("Failed to fetch reports from remote");
      const data = await res.json();
      return NextResponse.json(data);
    }

    // Local: read directories from nazitest_runs
    const entries = await readdir(NAZITEST_RUNS_PATH, { withFileTypes: true });
    const reportIds = entries
      .filter((e) => e.isDirectory() && !e.name.startsWith("."))
      .map((e) => e.name)
      .sort()
      .reverse();

    if (!withSummary) {
      return NextResponse.json({ reports: reportIds });
    }

    // Fetch summary for each report
    const reports = await Promise.all(
      reportIds.map(async (id) => {
        try {
          const reportPath = path.join(
            NAZITEST_RUNS_PATH,
            id,
            "report",
            "report.json"
          );
          const content = await readFile(reportPath, "utf-8");
          const { summary } = JSON.parse(content);
          return { id, summary: summary || null };
        } catch {
          return { id, summary: null };
        }
      })
    );

    return NextResponse.json({ reports });
  } catch (err) {
    console.error("Reports list error:", err);
    return NextResponse.json(
      { error: "Failed to load reports" },
      { status: 500 }
    );
  }
}
