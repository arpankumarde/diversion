"use client";

import { useState, useCallback } from "react";
import Image from "next/image";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { CopyIcon, CheckIcon } from "lucide-react";

// Purposes from models.yaml
const PURPOSES = [
  {
    key: "graph_builder",
    label: "Graph Builder",
    description: "Large context for ingesting full recon data",
  },
  {
    key: "strategist",
    label: "Strategist",
    description: "Strongest reasoning for hypothesis generation",
  },
  {
    key: "scout",
    label: "Scout",
    description: "Fast exploratory analysis",
  },
  {
    key: "exploit_planner",
    label: "Exploit Planner",
    description: "Agentic coding for exploit generation",
  },
  {
    key: "cross_validator",
    label: "Cross Validator",
    description: "Independent cross-validation",
  },
  {
    key: "codebase_analyzer",
    label: "Codebase Analyzer",
    description: "Strong code understanding",
  },
  {
    key: "report_writer",
    label: "Report Writer",
    description: "Executive summary and report generation",
  },
] as const;

// Models from OpenAI, Anthropic, Google (models.dev structure)
const MODELS = [
  // OpenAI
  { id: "openai/gpt-4o", name: "GPT-4o", provider: "openai" },
  { id: "openai/gpt-4o-mini", name: "GPT-4o Mini", provider: "openai" },
  { id: "openai/gpt-4-turbo", name: "GPT-4 Turbo", provider: "openai" },
  { id: "openai/gpt-4", name: "GPT-4", provider: "openai" },
  { id: "openai/o1", name: "o1", provider: "openai" },
  { id: "openai/o1-mini", name: "o1 Mini", provider: "openai" },
  // Anthropic
  { id: "anthropic/claude-sonnet-4-6", name: "Claude Sonnet 4.6", provider: "anthropic" },
  { id: "anthropic/claude-opus-4-6", name: "Claude Opus 4.6", provider: "anthropic" },
  { id: "anthropic/claude-3-5-sonnet-20241022", name: "Claude 3.5 Sonnet", provider: "anthropic" },
  { id: "anthropic/claude-3-5-haiku-20241022", name: "Claude 3.5 Haiku", provider: "anthropic" },
  { id: "anthropic/claude-3-opus-20240229", name: "Claude 3 Opus", provider: "anthropic" },
  // Google
  { id: "google/gemini-2.0-flash", name: "Gemini 2.0 Flash", provider: "google" },
  { id: "google/gemini-1.5-pro", name: "Gemini 1.5 Pro", provider: "google" },
  { id: "google/gemini-1.5-flash", name: "Gemini 1.5 Flash", provider: "google" },
  { id: "google/gemini-1.5-flash-8b", name: "Gemini 1.5 Flash 8B", provider: "google" },
  { id: "google/gemini-pro", name: "Gemini Pro", provider: "google" },
] as const;

const PROVIDER_LOGOS: Record<string, string> = {
  openai: "https://models.dev/logos/openai.svg",
  anthropic: "https://models.dev/logos/anthropic.svg",
  google: "https://models.dev/logos/google.svg",
};

const DUMMY_API_KEY = "sk-or-v1-dummy-key-placeholder-1234567890abcdef";

export default function SettingsPage() {
  const [modelByPurpose, setModelByPurpose] = useState<Record<string, string>>(
    Object.fromEntries(
      PURPOSES.map((p) => [p.key, "anthropic/claude-sonnet-4-6"])
    )
  );
  const [apiKey, setApiKey] = useState(DUMMY_API_KEY);
  const [copied, setCopied] = useState(false);

  const handleCopyKey = useCallback(async () => {
    if (apiKey) {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [apiKey]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="mt-2 text-muted-foreground">
          Configure models and API key for each purpose. Models use OpenRouter
          API.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>API Key</CardTitle>
          <CardDescription>
            OpenRouter API key used for all model requests. Value is hidden and
            can be copied.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 max-w-md">
            <Input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="font-mono text-xs"
            />
            <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={handleCopyKey}
              title="Copy API key"
            >
              {copied ? (
                <CheckIcon className="size-4 text-green-600" />
              ) : (
                <CopyIcon className="size-4" />
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 sm:grid-cols-2">
        {PURPOSES.map((purpose) => {
          const modelId = modelByPurpose[purpose.key];
          const model = MODELS.find((m) => m.id === modelId);
          return (
            <Card key={purpose.key}>
              <CardHeader>
                <CardTitle>{purpose.label}</CardTitle>
                <CardDescription>{purpose.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <Label htmlFor={`model-${purpose.key}`}>Model</Label>
                  <Select
                    value={modelId}
                    onValueChange={(v) =>
                      setModelByPurpose((prev) => ({
                        ...prev,
                        [purpose.key]: v,
                      }))
                    }
                  >
                    <SelectTrigger
                      id={`model-${purpose.key}`}
                      className="w-full"
                    >
                      <SelectValue placeholder="Select a model" />
                    </SelectTrigger>
                    <SelectContent>
                      {MODELS.map((m) => (
                        <SelectItem key={m.id} value={m.id}>
                          <span className="flex items-center gap-2">
                            <Image
                              src={PROVIDER_LOGOS[m.provider]}
                              alt=""
                              width={16}
                              height={16}
                              className="shrink-0 dark:invert"
                              unoptimized
                            />
                            {m.name}
                            <span className="text-muted-foreground">
                              ({m.id})
                            </span>
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
