import type { LucideIcon } from "lucide-react";
import {
  Lock,
  Eye,
  Server,
  Network,
  BrainCircuit,
  Target,
  Activity,
  Zap,
} from "lucide-react";

export const navLinks = [
  { href: "#thesis", label: "Core Thesis" },
  { href: "#flow", label: "Process Flow" },
  { href: "#modules", label: "Capabilities" },
  { href: "#security", label: "Security" },
] as const;

export const thesisBullets = [
  "Real browser reconnaissance via CDP, not synthetic HTTP requests",
  "Full-spectrum recording of DOM, HAR, and WebSockets",
  "LLM reasoning over an adaptive knowledge graph",
  "Autonomous exploitation with strategy rotation",
] as const;

export const workflowSteps: ReadonlyArray<{
  icon: LucideIcon;
  title: string;
  desc: string;
}> = [
    { icon: Lock, title: "Authorize", desc: "Confirm scope & legal boundaries" },
    { icon: Eye, title: "Recon", desc: "CDP-driven browser crawling" },
    { icon: Server, title: "Record", desc: "Capture HAR, DOM & JSON" },
    { icon: Network, title: "Model", desc: "Build knowledge graph" },
    { icon: BrainCircuit, title: "Reason", desc: "LLM vulnerability hypotheses" },
    { icon: Target, title: "Exploit", desc: "curl_cffi & browser replay" },
  ];

export const coreModules: Array<{
  icon: any;
  title: string;
  description: string;
  iconClass: string;
  wide?: boolean;
}> = [
  {
    icon: Eye,
    title: "Zendriver Recon Engine",
    description:
      "Direct CDP control bypassing Cloudflare & Akamai. Captures client-side rendering, WebSockets, CSRF tokens, and anti-bot challenges natively.",
    iconClass: "bg-teal-500/10 border-teal-500/20 text-teal-400",
  },
  {
    icon: Network,
    title: "Knowledge Graph Builder",
    description:
      "Constructs a relational map of endpoints, parameters, data flows, and auth scopes using NetworkX. Local-first and highly scalable.",
    iconClass: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
  },
  {
    icon: BrainCircuit,
    title: "Multi-Agent Reasoning",
    description:
      "Utilizes Opus, Sonnet, and DeepSeek via OpenRouter to generate, refine, and cross-validate vulnerability hypotheses based on graph evidence.",
    iconClass: "bg-teal-500/10 border-teal-500/20 text-teal-400",
  },
  {
    icon: Activity,
    title: "Adaptive Exploitation Engine",
    description:
      "TLS-fingerprint safe exploitation via `curl_cffi` to evade WAFs. Implements exponential backoff and automatic strategy rotation (encoding, delivery, identity) when blocked. Confirms vulnerabilities with zero false positives.",
    iconClass: "bg-red-500/10 border-red-500/20 text-red-400",
    wide: true,
  },
  {
    icon: Zap,
    title: "Full-Spectrum Recording",
    description:
      "Every request, response, DOM mutation, and WebSocket frame is captured as structured HAR + JSON. Nothing is lost.",
    iconClass: "bg-teal-500/10 border-teal-500/20 text-teal-400",
  },
] as any;

export const comparisonRows = [
  {
    primitive: "Real browser recon",
    burp: "Proxy-based (partial)",
    nuclei: "HTTP only",
    manual: "Yes",
    nazitest: "Yes (CDP)",
  },
  {
    primitive: "Mental model",
    burp: "None",
    nuclei: "Template matching",
    manual: "Yes (brain)",
    nazitest: "Knowledge graph",
  },
  {
    primitive: "Hypothesis generation",
    burp: "Rule-based",
    nuclei: "Signature-based",
    manual: "Creative reasoning",
    nazitest: "LLM reasoning",
  },
  {
    primitive: "Adaptive strategy",
    burp: "None",
    nuclei: "None",
    manual: "Yes",
    nazitest: "LLM + backoff loops",
  },
] as const;

export const codeSnippetLines = [
  { key: "recon", value: "Observe the system as a user would" },
  { key: "model", value: "Build a mental model of how it works" },
  { key: "hypothesize", value: "Generate theories about what could break" },
  { key: "validate", value: "Test theories against the live system" },
  { key: "adapt", value: "When blocked, change strategy" },
  { key: "chain", value: "Combine small findings into exploits" },
] as const;
