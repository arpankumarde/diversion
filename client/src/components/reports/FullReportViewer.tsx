"use client";

import { useState, useEffect } from "react";
import { useUser } from "@auth0/nextjs-auth0/client";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { addAuditLog } from "@/lib/audit-logs";

const DEFAULT_PASSPHRASE = "access";

export function FullReportViewer({
  reportHtmlUrl,
  reportId,
}: {
  reportHtmlUrl: string;
  reportId: string;
}) {
  const [hasAccess, setHasAccess] = useState(false);
  const [modalOpen, setModalOpen] = useState(true);
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");

  const { user } = useUser();
  const expectedPassphrase =
    process.env.NEXT_PUBLIC_REPORT_PASSPHRASE || DEFAULT_PASSPHRASE;

  useEffect(() => {
    if (!hasAccess) {
      setTimeout(() => {
        setModalOpen(true);
      }, 100);
    }
  }, [hasAccess]);

  const handleAccess = () => {
    setError("");
    if (!passphrase.trim()) {
      setError("Please enter a passphrase");
      return;
    }
    if (passphrase.trim() !== expectedPassphrase) {
      setError("Incorrect passphrase");
      return;
    }
    addAuditLog({
      user: user?.email ?? "anonymous",
      reportId,
      viewedAt: new Date().toISOString(),
    });
    setHasAccess(true);
    setModalOpen(false);
  };

  return (
    <div className="relative">
      <div
        className={cn(
          "transition-all duration-300",
          !hasAccess && "select-none pointer-events-none blur-md",
        )}
      >
        <iframe
          src={reportHtmlUrl}
          title="Full security report"
          className="h-[87dvh] w-full min-h-[500px] bg-white"
          sandbox="allow-scripts allow-same-origin"
          style={{ colorScheme: "light" }}
        />
      </div>

      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent
          className="sm:max-w-md"
          showCloseButton={false}
          onPointerDownOutside={(e) => e.preventDefault()}
          onEscapeKeyDown={(e) => e.preventDefault()}
        >
          <DialogHeader>
            <DialogTitle>Enter passphrase</DialogTitle>
            <DialogDescription>
              Enter the passphrase to view the full security report.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <Input
              type="password"
              placeholder="Passphrase"
              value={passphrase}
              onChange={(e) => {
                setPassphrase(e.target.value);
                setError("");
              }}
              onKeyDown={(e) => e.key === "Enter" && handleAccess()}
              className={error ? "border-destructive" : ""}
              autoFocus
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter>
            <Button onClick={handleAccess}>Access now</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
