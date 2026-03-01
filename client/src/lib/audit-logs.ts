const STORAGE_KEY = "report-audit-logs";
const MAX_LOGS = 20;

export interface AuditLog {
  id: string;
  user: string;
  reportId: string;
  viewedAt: string;
}

function getStoredLogs(): AuditLog[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as AuditLog[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function setStoredLogs(logs: AuditLog[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(logs));
  } catch {
    // ignore
  }
}

export function getAuditLogs(): AuditLog[] {
  return getStoredLogs();
}

export function addAuditLog(entry: Omit<AuditLog, "id">): void {
  const logs = getStoredLogs();
  const newLog: AuditLog = {
    ...entry,
    id: crypto.randomUUID(),
  };
  const updated = [newLog, ...logs].slice(0, MAX_LOGS);
  setStoredLogs(updated);
}
