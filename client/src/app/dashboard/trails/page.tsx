import { AuditTrailsTable } from "@/components/dashboard/AuditTrailsTable";

const Page = () => {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Audit trails</h1>
      <p className="mt-2 text-muted-foreground">
        Who viewed which full report and when. Entries are logged when access is
        granted via passphrase. Last 20 entries stored in this browser.
      </p>

      <AuditTrailsTable />
    </div>
  );
};

export default Page;
