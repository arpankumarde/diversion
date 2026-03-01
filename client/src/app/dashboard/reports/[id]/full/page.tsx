import { getReportHtmlUrl } from "../page";
import { FullReportViewer } from "@/components/reports/FullReportViewer";

const Page = async ({ params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const reportHtmlUrl = getReportHtmlUrl(id);

  if (!reportHtmlUrl) {
    return <div>Report not found</div>;
  }

  return (
    <div>
      <FullReportViewer reportHtmlUrl={reportHtmlUrl} reportId={id} />
    </div>
  );
};

export default Page;
