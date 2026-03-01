import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import path from "path";

const REPORTS_SOURCE = process.env.REPORTS_SOURCE || "local";
const REPORTS_API_URL =
  process.env.REPORTS_API_URL || process.env.NEXT_PUBLIC_API_URL || "";
const NAZITEST_RUNS_PATH = path.join(process.cwd(), "..", "nazitest_runs");

function isValidId(id: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(id) && !id.includes("..");
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  if (!id || !isValidId(id)) {
    return NextResponse.json({ error: "Invalid report ID" }, { status: 400 });
  }

  try {
    // Remote: API serves /runs/<RUNID>/* with same folder structure as nazitest_runs
    if (REPORTS_SOURCE === "remote" && REPORTS_API_URL) {
      const base = REPORTS_API_URL.replace(/\/$/, "");
      const [reportRes, metaRes, configRes] = await Promise.all([
        fetch(`${base}/runs/${id}/report/report.json`),
        fetch(`${base}/runs/${id}/report/meta.json`),
        fetch(`${base}/runs/${id}/config.json`),
      ]);

      const report = reportRes.ok ? await reportRes.json() : null;
      const meta = metaRes.ok ? await metaRes.json() : null;
      const config = configRes.ok ? await configRes.json() : null;

      if (!report && !meta) {
        return NextResponse.json({ error: "Report not found" }, { status: 404 });
      }

      return NextResponse.json({ report, meta, config });
    }

    // Local: read from filesystem
    const reportDir = path.join(NAZITEST_RUNS_PATH, id);
    const [report, meta, config] = await Promise.all([
      readFile(path.join(reportDir, "report", "report.json"), "utf-8").then(
        (s) => JSON.parse(s),
        () => null
      ),
      readFile(path.join(reportDir, "report", "meta.json"), "utf-8").then(
        (s) => JSON.parse(s),
        () => null
      ),
      readFile(path.join(reportDir, "config.json"), "utf-8").then(
        (s) => JSON.parse(s),
        () => null
      ),
    ]);

    if (!report && !meta) {
      return NextResponse.json({ error: "Report not found" }, { status: 404 });
    }

    return NextResponse.json({ report, meta, config });
  } catch (err) {
    console.error("Report fetch error:", err);
    return NextResponse.json(
      { error: "Failed to load report" },
      { status: 500 }
    );
  }
}
