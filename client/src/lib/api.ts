import axios from "axios";

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
});

export interface StartScanBody {
  target: string;
  repo: string;
  depth?: number;
  pages?: number;
  time_limit?: string;
  proxy?: string;
}

export interface StartScanResponse {
  status: string;
  run_id: string;
}

export async function startScan(body: StartScanBody) {
  const { data } = await api.post<StartScanResponse>("/api/scans/start", {
    target: body.target,
    repo: body.repo,
    depth: body.depth ?? 5,
    pages: body.pages ?? 200,
    time_limit: body.time_limit ?? "120",
    proxy: body.proxy ?? "",
  });
  return data;
}

export async function stopScan(runId: string) {
  const { data } = await api.post(`/api/scans/${runId}/stop`);
  return data;
}
