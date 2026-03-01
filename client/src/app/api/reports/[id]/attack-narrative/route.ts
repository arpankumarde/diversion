import { NextRequest, NextResponse } from "next/server";

const API_BASE =
  process.env.REPORTS_API_URL || process.env.NEXT_PUBLIC_API_URL || "";
const TRIGGER_TIMEOUT_MS = 10_000;

function isValidId(id: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(id) && !id.includes("..");
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  if (!id || !isValidId(id)) {
    return NextResponse.json({ error: "Invalid report ID" }, { status: 400 });
  }

  const base = API_BASE.replace(/\/$/, "");
  if (!base || !base.startsWith("http")) {
    return NextResponse.json(
      { error: "API base URL not configured" },
      { status: 503 },
    );
  }

  try {
    const narrativeRes = await fetch(
      `${base}/runs/${id}/report/attack_narrative.md`,
      { cache: "no-store" },
    );

    if (narrativeRes.ok) {
      const text = await narrativeRes.text();
      return new NextResponse(text, {
        headers: {
          "Content-Type": "text/markdown; charset=utf-8",
          "Cache-Control": "public, max-age=60",
        },
      });
    }

    if (narrativeRes.status === 404) {
      const triggerUrl = `${base}/api/reports/${id}/attack-narrative`;
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        TRIGGER_TIMEOUT_MS,
      );

      try {
        await fetch(triggerUrl, {
          method: "POST",
          signal: controller.signal,
          headers: { "Content-Type": "application/json" },
        });
      } catch {
        // Timeout or network error - assume process may have started
      } finally {
        clearTimeout(timeoutId);
      }

      return NextResponse.json({ status: "generating" }, { status: 202 });
    }

    return NextResponse.json(
      { error: "Failed to fetch attack narrative" },
      { status: narrativeRes.status },
    );
  } catch (err) {
    console.error("Attack narrative proxy error:", err);
    return NextResponse.json(
      { error: "Failed to load attack narrative" },
      { status: 500 },
    );
  }
}
