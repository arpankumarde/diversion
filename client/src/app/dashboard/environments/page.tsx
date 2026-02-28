"use client";

import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { PlusIcon, ExternalLinkIcon } from "lucide-react";

const ENVIRONMENT_TAGS = [
  {
    value: "DEVELOPMENT",
    label: "Development",
    color: "bg-sky-400",
    theme: "bg-sky-400/10 text-sky-400 border-sky-400/20"
  },
  {
    value: "STAGING",
    label: "Staging",
    color: "bg-amber-500",
    theme: "bg-amber-500/10 text-amber-500 border-amber-500/20"
  },
  {
    value: "PRODUCTION",
    label: "Production",
    color: "bg-emerald-500",
    theme: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
  },
] as const;

type EnvironmentTag = (typeof ENVIRONMENT_TAGS)[number]["value"];

interface Environment {
  id: string;
  name: string;
  tag: EnvironmentTag;
  endpoint: string;
}

const HARDCODED_ENVIRONMENTS: Environment[] = [
  {
    id: "1",
    name: "dev-aws-1",
    tag: "DEVELOPMENT",
    endpoint: "https://api.dev.example.com/v1",
  },
  {
    id: "2",
    name: "staging-eu-1",
    tag: "STAGING",
    endpoint: "https://api.staging.example.com/v1",
  },
  {
    id: "3",
    name: "prod-us-east-1",
    tag: "PRODUCTION",
    endpoint: "https://api.example.com/v1",
  },
  {
    id: "4",
    name: "dev-local",
    tag: "DEVELOPMENT",
    endpoint: "http://localhost:3000/api",
  },
  {
    id: "5",
    name: "staging-aws-2",
    tag: "STAGING",
    endpoint: "https://api.staging-2.example.com/v1",
  },
];

function getTagVariant(
  tag: EnvironmentTag
): "default" | "secondary" | "destructive" | "outline" {
  switch (tag) {
    case "PRODUCTION":
      return "destructive";
    case "STAGING":
      return "secondary";
    case "DEVELOPMENT":
    default:
      return "outline";
  }
}

export default function EnvironmentsPage() {
  const [environments, setEnvironments] =
    useState<Environment[]>(HARDCODED_ENVIRONMENTS);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [formName, setFormName] = useState("");
  const [formTag, setFormTag] = useState<EnvironmentTag>("DEVELOPMENT");
  const [formEndpoint, setFormEndpoint] = useState("");

  const handleAddEnvironment = () => {
    if (!formName.trim() || !formEndpoint.trim()) return;

    // URL Validation
    try {
      new URL(formEndpoint.trim());
    } catch (e) {
      return;
    }

    const newEnv: Environment = {
      id: crypto.randomUUID(),
      name: formName.trim(),
      tag: formTag,
      endpoint: formEndpoint.trim(),
    };
    setEnvironments((prev) => [...prev, newEnv]);
    setFormName("");
    setFormTag("DEVELOPMENT");
    setFormEndpoint("");
    setDialogOpen(false);
  };

  const handleOpenChange = (open: boolean) => {
    setDialogOpen(open);
    if (!open) {
      setFormName("");
      setFormTag("DEVELOPMENT");
      setFormEndpoint("");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Environments</h1>
          <p className="mt-2 text-muted-foreground">
            Configure environments with name, tag, and endpoint for testing.
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={handleOpenChange}>
          <DialogTrigger asChild>
            <Button>
              <PlusIcon className="size-4" />
              Add environment
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Add environment</DialogTitle>
              <DialogDescription>
                Create a new environment with a name, tag, and endpoint.
              </DialogDescription>
            </DialogHeader>
            <div className="mt-6 space-y-4">
              <div className="space-y-2">
                <Label htmlFor="env-name">Name</Label>
                <Input
                  id="env-name"
                  placeholder="e.g. dev-aws-1"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="env-tag">Tag</Label>
                <Select
                  value={formTag}
                  onValueChange={(v) => setFormTag(v as EnvironmentTag)}
                >
                  <SelectTrigger id="env-tag">
                    <SelectValue placeholder="Select tag" />
                  </SelectTrigger>
                  <SelectContent>
                    {ENVIRONMENT_TAGS.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        <div className="flex items-center gap-2 w-32">
                          <div className={`h-2 w-2 rounded-full ${t.color}`} />
                          {t.label}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="env-endpoint">Endpoint</Label>
                <Input
                  id="env-endpoint"
                  type="url"
                  placeholder="https://api.example.com/v1"
                  value={formEndpoint}
                  onChange={(e) => setFormEndpoint(e.target.value)}
                />
              </div>
              <Button
                className="w-full"
                onClick={handleAddEnvironment}
                disabled={!formName.trim() || !formEndpoint.trim()}
              >
                Add environment
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {environments.map((env) => (
          <Card key={env.id} className="bg-muted/30 border-sidebar-border/50 hover:bg-muted/50 hover:border-sidebar-ring/50 transition-colors shadow-sm">
            <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
              <div className="space-y-1">
                <CardTitle className="text-base">{env.name}</CardTitle>
                <div className="flex items-center gap-2">
                  {(() => {
                    const tagInfo = ENVIRONMENT_TAGS.find((t) => t.value === env.tag);
                    return (
                      <Badge
                        variant="outline"
                        className={`text-[10px] uppercase tracking-wider h-5 gap-1.5 px-2 font-semibold border-none ${tagInfo?.theme}`}
                      >
                        <div className={`h-1.5 w-1.5 rounded-full shrink-0 ${tagInfo?.color}`} />
                        {env.tag}
                      </Badge>
                    );
                  })()}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <p className="mb-3 truncate text-xs text-muted-foreground font-mono">
                {env.endpoint}
              </p>
              <Button variant="outline" size="sm" className="w-full" asChild>
                <a
                  href={env.endpoint}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2"
                >
                  <ExternalLinkIcon className="size-3" />
                  Test endpoint
                </a>
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
