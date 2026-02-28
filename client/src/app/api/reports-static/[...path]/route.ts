import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import path from "path";

const NAZITEST_RUNS_PATH = path.join(process.cwd(), "..", "nazitest_runs");

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".css": "text/css",
  ".js": "application/javascript",
  ".ico": "image/x-icon",
};

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const pathSegments = (await params).path;
  if (!pathSegments?.length) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const id = pathSegments[0];
  if (!/^[a-zA-Z0-9_-]+$/.test(id) || id.includes("..")) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }

  const filePath = path.join(NAZITEST_RUNS_PATH, ...pathSegments);
  const resolved = path.resolve(filePath);

  if (!resolved.startsWith(path.resolve(NAZITEST_RUNS_PATH))) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }

  try {
    const content = await readFile(filePath);
    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    return new NextResponse(content, {
      headers: {
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=3600",
      },
    });
  } catch {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
}
