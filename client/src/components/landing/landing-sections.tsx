"use client";

import {
  ShieldAlert,
  Terminal,
  CheckCircle2,
  ChevronRight,
  Lock,
  LogIn,
} from "lucide-react";
import { useUser } from "@auth0/nextjs-auth0/client";
import { Button } from "@/components/ui/button";
import {
  navLinks,
  thesisBullets,
  workflowSteps,
  coreModules,
  comparisonRows,
  codeSnippetLines,
} from "@/app/landing-data";
import { cn } from "@/lib/utils";
import Link from "next/link";

const sectionCls = "py-24 border-t border-white/5";
const headingCls = "text-3xl font-bold text-white mb-4";
const subtextCls = "text-slate-400 text-lg";

export function LandingNav() {
  const { user, isLoading } = useUser();

  return (
    <nav className="sticky top-0 z-10 border-b border-white/5 bg-slate-950/50 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2 text-teal-400 font-mono font-bold tracking-wider text-xl">
          <ShieldAlert className="w-6 h-6 text-teal-500" />
          <span>NAZITEST</span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="hover:text-teal-400 transition-colors"
            >
              {link.label}
            </Link>
          ))}
        </div>
        <div className="flex items-center gap-2">
          {isLoading ? (
            <span className="text-slate-500 text-sm">...</span>
          ) : user ? (
            <>
              <Button
                asChild
                className="rounded-md bg-teal-500 text-slate-950 hover:bg-teal-400 font-bold ml-2 transition-transform hover:scale-105"
              >
                <Link href="/dashboard/home">Dashboard</Link>
              </Button>
            </>
          ) : (
            <Button
              variant="outline"
              size="sm"
              asChild
              className="rounded-md bg-teal-500/10 text-teal-400 border-teal-500/20 hover:bg-teal-500/20 hover:border-teal-500/40 hover:text-teal-300"
            >
              <a href="/auth/login">
                <LogIn className="w-4 h-4 sm:mr-1" />
                <span className="hidden sm:inline">Login</span>
              </a>
            </Button>
          )}
        </div>
      </div>
    </nav>
  );
}

export function HeroSection() {
  return (
    <section className="relative pt-12 pb-16 min-h-[75vh] flex items-center">
      {/* Background radial glow */}
      <div className="absolute top-1/2 left-0 -translate-y-1/2 w-[600px] h-[600px] bg-teal-500/10 blur-[150px] rounded-full pointer-events-none" />

      <div className="relative z-10 w-full grid lg:grid-cols-2 gap-16 items-center animate-in fade-in slide-in-from-bottom-8 duration-1000">
        {/* Left Column: Text & CTA */}
        <div className="flex flex-col items-start text-left space-y-8">
          {/* Sleek Pill Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.08] text-slate-300 text-xs font-medium backdrop-blur-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse shadow-[0_0_8px_1px_rgba(45,212,191,0.5)]" />
            NAZITEST v1.0 Preview
          </div>

          {/* Premium Typography Heading */}
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-b from-white to-white/70 leading-[1.1]">
            The standard for <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-emerald-400">
              Autonomous Pentesting
            </span>
          </h1>

          {/* Refined Subtext */}
          <p className="max-w-xl leading-relaxed text-slate-400 text-lg md:text-xl font-normal">
            Combining deep browser reconnaissance with multi-agent reasoning.
            The ultimate force multiplier for sophisticated security teams.
          </p>

          {/* Elevated Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-4 pt-4 w-full sm:w-auto">
            <Button
              size="lg"
              className="w-full sm:w-auto h-12 px-8 rounded-full bg-white text-slate-950 font-semibold text-base hover:bg-slate-200 transition-colors shadow-lg shadow-white/5 gap-2"
            >
              <Terminal className="w-4 h-4" />
              Initialize Platform
            </Button>
            <Button
              variant="outline"
              size="lg"
              className="w-full sm:w-auto h-12 px-8 rounded-full bg-white/[0.03] text-slate-200 border-white/10 hover:bg-white/[0.08] hover:border-white/20 transition-all gap-2 text-base font-medium backdrop-blur-sm"
            >
              View Architecture
              <ChevronRight className="w-4 h-4 text-slate-400" />
            </Button>
          </div>
        </div>

        {/* Right Column: Terminal Mockup */}
        <div className="hidden lg:block relative perspective-1000">
          <div className="relative w-full aspect-square max-h-[500px] bg-[#0c0c0c]/80 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl overflow-hidden p-6 flex flex-col font-mono text-sm leading-relaxed transform rotate-y-[-10deg] rotate-x-[5deg] transition-transform hover:rotate-y-0 hover:rotate-x-0 duration-700">
            {/* Window Controls */}
            <div className="flex items-center gap-2 mb-6">
              <div className="w-3 h-3 rounded-full bg-slate-700/50" />
              <div className="w-3 h-3 rounded-full bg-slate-700/50" />
              <div className="w-3 h-3 rounded-full bg-slate-700/50" />
            </div>

            {/* Terminal Output */}
            <div className="flex-1 space-y-3 opacity-90">
              <div className="flex text-slate-500">
                <span className="text-teal-500 mr-2">❯</span> nazi-cli init
                --target api.production.com
              </div>
              <div className="text-slate-400">
                [08:24:12] Authenticating via stored CDP session...
              </div>
              <div className="text-teal-400">
                [08:24:14] Success. DOM context established.
              </div>
              <div className="text-slate-400">
                [08:24:16] Mapping routes and GraphQL endpoints...
              </div>
              <div className="text-slate-400">
                [08:24:19] Discovered 42 endpoints. Extracting fragments...
              </div>
              <div className="text-emerald-400">
                [08:24:22] LLM Agent evaluating mutation vectors...
              </div>
              <div className="flex items-center gap-2 mt-4 text-slate-500">
                <span className="w-1.5 h-4 bg-teal-500 animate-pulse" />
                Processing hypothesis tree
              </div>
            </div>
            {/* Deep glow under terminal */}
            <div className="absolute -bottom-20 -right-20 w-64 h-64 bg-emerald-500/20 blur-[100px] rounded-full pointer-events-none" />
          </div>
        </div>
      </div>
    </section>
  );
}

export function ThesisSection() {
  return (
    <section id="thesis" className={sectionCls}>
      <div className="grid md:grid-cols-2 gap-16 items-center">
        <div className="space-y-6">
          <h2 className={headingCls}>The Missing 82%</h2>
          <p className={cn(subtextCls, "leading-relaxed")}>
            Current tools fall into two camps: dumb automation that fires known
            signatures, and expensive manual human labor. The gap between
            them—business logic flaws, chained exploits, context-aware
            authentication bypasses—is where 82% of real-world breaches occur.
          </p>
          <ul className="space-y-4 pt-4">
            {thesisBullets.map((item, i) => (
              <li key={i} className="flex items-start gap-3">
                <CheckCircle2 className="w-6 h-6 text-teal-500 shrink-0" />
                <span className="text-slate-300">{item}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-teal-500/20 to-emerald-500/20 blur-3xl rounded-full" />
          <div className="relative bg-slate-900 border border-white/10 rounded-2xl p-8 shadow-2xl font-mono text-sm">
            <div className="flex items-center gap-2 mb-6 border-b border-white/10 pb-4">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <div className="w-3 h-3 rounded-full bg-yellow-500" />
              <div className="w-3 h-3 rounded-full bg-green-500" />
              <span className="ml-2 text-slate-500">PENTESTER_WORKFLOW.py</span>
            </div>
            <div className="space-y-2 text-slate-300">
              {codeSnippetLines.map((line) => (
                <p key={line.key}>
                  <span className="text-teal-400">&quot;{line.key}&quot;</span>:
                  &quot;{line.value}&quot;
                </p>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function FlowSection() {
  return (
    <section id="flow" className={sectionCls}>
      <div className="text-center max-w-3xl mx-auto mb-16">
        <h2 className={headingCls}>Autonomous Process Flow</h2>
        <p className={subtextCls}>
          A state machine mirroring the cognitive cycle of a seasoned security
          researcher.
        </p>
      </div>

      <div className="relative">
        <div className="hidden lg:block absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-teal-500/10 via-teal-500/40 to-emerald-500/10 -translate-y-1/2" />
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-6 relative">
          {workflowSteps.map((step, index) => (
            <div
              key={index}
              className="relative bg-slate-900 border border-white/10 rounded-xl p-6 text-center hover:border-teal-500/50 transition-colors z-10 group"
            >
              <div className="w-12 h-12 mx-auto bg-slate-950 border border-teal-500/30 rounded-full flex items-center justify-center mb-4 group-hover:scale-110 group-hover:bg-teal-500/10 transition-all">
                <step.icon className="w-5 h-5 text-teal-400" />
              </div>
              <h3 className="text-white font-semibold mb-2">{step.title}</h3>
              <p className="text-slate-400 text-sm">{step.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export function ModulesSection() {
  return (
    <section id="modules" className={sectionCls}>
      <div className="mb-16">
        <h2 className={headingCls}>Core Modules</h2>
        <p className={subtextCls}>
          Engineered from first principles to handle modern, JS-heavy web
          architectures.
        </p>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {coreModules.map((mod, i) => {
          const Icon = mod.icon;
          return (
            <div
              key={i}
              className={cn(
                "bg-linear-to-b from-slate-900 to-slate-950 border border-white/10 rounded-2xl p-8 hover:border-teal-500/30 transition-all",
                mod.wide && "lg:col-span-2",
              )}
            >
              <div
                className={cn(
                  "w-10 h-10 rounded-lg flex items-center justify-center mb-6 border",
                  mod.iconClass,
                )}
              >
                <Icon className="w-5 h-5" />
              </div>
              <h3 className="text-xl font-bold text-white mb-3">{mod.title}</h3>
              <p className="text-slate-400 leading-relaxed">
                {mod.description}
              </p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function ComparisonSection() {
  return (
    <section className={sectionCls}>
      <div className="mb-16 text-center">
        <h2 className={headingCls}>Competitive Landscape</h2>
        <p className={subtextCls}>
          Why NAZITEST outperforms existing paradigms.
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/10 text-slate-400">
              <th className="py-4 px-6 font-medium">Primitive</th>
              <th className="py-4 px-6 font-medium">Burp/ZAP</th>
              <th className="py-4 px-6 font-medium">Nuclei</th>
              <th className="py-4 px-6 font-medium">Manual Pentester</th>
              <th className="py-4 px-6 font-semibold text-teal-400">
                NAZITEST
              </th>
            </tr>
          </thead>
          <tbody className="text-slate-300">
            {comparisonRows.map((row, i) => (
              <tr
                key={i}
                className="border-b border-white/5 hover:bg-white/[0.02] transition-colors last:border-b-0"
              >
                <td className="py-4 px-6">{row.primitive}</td>
                <td className="py-4 px-6 text-slate-500">{row.burp}</td>
                <td className="py-4 px-6 text-slate-500">{row.nuclei}</td>
                <td className="py-4 px-6 text-emerald-400">{row.manual}</td>
                <td className="py-4 px-6 text-teal-400 font-medium">
                  {row.nazitest}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function SecuritySection() {
  return (
    <section id="security" className={sectionCls}>
      <div className="bg-red-950/20 border border-red-500/20 rounded-3xl p-8 md:p-12 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <ShieldAlert className="w-64 h-64 text-red-500" />
        </div>

        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-sm font-semibold mb-6">
            <Lock className="w-4 h-4" />
            STRICT AUTHORIZATION GATE
          </div>

          <h2 className={headingCls}>Unauthorized Testing is Illegal</h2>
          <p className="text-slate-300 text-lg leading-relaxed mb-8">
            NAZITEST is engineered exclusively for authorized penetration
            testing and security research. The system is hardcoded to require
            explicit written authorization confirmation, strict scope
            enforcement, and mandatory data sanitization.
          </p>

          <div className="grid sm:grid-cols-2 gap-4">
            <div className="bg-slate-900/50 border border-white/5 rounded-xl p-4">
              <h4 className="font-semibold text-white mb-1">Strict Scope</h4>
              <p className="text-sm text-slate-400">
                Enforced domain whitelists and safe-mode defaults blocking
                destructive methods.
              </p>
            </div>
            <div className="bg-slate-900/50 border border-white/5 rounded-xl p-4">
              <h4 className="font-semibold text-white mb-1">Data Protection</h4>
              <p className="text-sm text-slate-400">
                LLM data sanitization strips raw credentials before external API
                routing.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function LandingFooter() {
  return (
    <footer className="border-t border-white/5 bg-slate-950 mt-12 py-12">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-2 text-slate-400 font-mono font-bold tracking-wider">
          <ShieldAlert className="w-5 h-5 text-teal-500" />
          <span>NAZITEST</span>
        </div>
        <p className="text-slate-500 text-sm">
          © 2026 System Design Engineering. All rights reserved. CONFIDENTIAL.
        </p>
      </div>
    </footer>
  );
}
