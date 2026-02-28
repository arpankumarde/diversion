import {
  LandingNav,
  HeroSection,
  ThesisSection,
  FlowSection,
  ModulesSection,
  ComparisonSection,
  SecuritySection,
  LandingFooter,
} from "@/components/landing/landing-sections";

export default function Page() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-200 selection:bg-teal-500/30 font-sans overflow-hidden">
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-teal-900/20 blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-emerald-900/10 blur-[120px]" />
      </div>

      <LandingNav />

      <div className="relative z-10 max-w-7xl mx-auto px-6">
        <HeroSection />
        <ThesisSection />
        <FlowSection />
        <ModulesSection />
        <ComparisonSection />
        <SecuritySection />
      </div>

      <LandingFooter />
    </main>
  );
}
