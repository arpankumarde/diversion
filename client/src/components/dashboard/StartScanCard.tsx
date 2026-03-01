"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Play, Square, Loader2, Clock } from "lucide-react";
import { startScan, stopScan } from "@/lib/api";
import { DEFAULT_ENVIRONMENTS } from "@/lib/environments";

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function StartScanCard() {
  const [selectedEnvId, setSelectedEnvId] = useState<string>("");
  const [runId, setRunId] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [isStopped, setIsStopped] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedEnv = DEFAULT_ENVIRONMENTS.find((e) => e.id === selectedEnvId);
  const isScanning = runId !== null && !isStopped;

  // Elapsed timer
  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => setElapsedSeconds((s) => s + 1), 1000);
    return () => clearInterval(interval);
  }, [isScanning]);

  const handleStart = async () => {
    if (!selectedEnv) {
      setError("Please select an environment.");
      return;
    }
    setError(null);
    setIsStarting(true);
    try {
      const res = await startScan({
        target: selectedEnv.target,
        repo: selectedEnv.repo,
      });
      if (res.status === "success" || res.run_id) {
        setRunId(res.run_id);
        setElapsedSeconds(0);
      } else {
        setError(res.status || "Failed to start scan.");
      }
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Failed to start scan. Check API connection.",
      );
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    if (!runId) return;
    setIsStopping(true);
    setError(null);
    try {
      await stopScan(runId);
      setIsStopped(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Failed to stop scan. Check API connection.",
      );
    } finally {
      setIsStopping(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Start new scan</CardTitle>
        <CardDescription>
          Choose an environment and start a vulnerability scan. The browser will
          open for recording.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isScanning && !isStopped && (
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Environment</label>
              <Select
                value={selectedEnvId}
                onValueChange={(v) => {
                  setSelectedEnvId(v);
                  setError(null);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select environment" />
                </SelectTrigger>
                <SelectContent>
                  {DEFAULT_ENVIRONMENTS.map((env) => (
                    <SelectItem key={env.id} value={env.id} className="py-1">
                      <div className="flex flex-col items-start">
                        <span>{env.name}</span>
                        <span className="text-xs text-muted-foreground font-mono">
                          {env.target}
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={handleStart}
              disabled={!selectedEnvId || isStarting}
              className="w-full sm:w-auto"
            >
              {isStarting ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Play className="size-4" />
              )}
              <span className="ml-2">Start scan</span>
            </Button>
          </div>
        )}

        {isScanning && (
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:gap-6">
            <div className="flex items-center gap-2 text-muted-foreground">
              <Clock className="size-4" />
              <span className="font-mono tabular-nums">
                Elapsed: {formatElapsed(elapsedSeconds)}
              </span>
            </div>
            <Button
              variant="destructive"
              onClick={handleStop}
              disabled={isStopping}
              className="w-full sm:w-auto"
            >
              {isStopping ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Square className="size-4" />
              )}
              <span className="ml-2">Stop recording</span>
            </Button>
          </div>
        )}

        {isStopped && (
          <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 text-sm">
            <p className="font-medium text-primary">Scan stopped</p>
            <p className="mt-1 text-muted-foreground">
              Our system is processing the inputs. The report will be generated
              after ~15 minutes.
            </p>
          </div>
        )}

        {error && <p className="text-sm text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}
