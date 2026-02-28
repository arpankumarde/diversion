"""Codebase cross-reference — tree-sitter AST route extraction and taint analysis."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Dangerous sinks per PRD section 8
DANGEROUS_SINKS: dict[str, list[str]] = {
    "sql": ["execute", "raw", "query", "cursor"],
    "command": ["exec", "spawn", "system", "popen", "subprocess"],
    "file": ["readFile", "writeFile", "open", "unlink"],
    "template": ["render", "template", "eval"],
    "redirect": ["redirect", "location", "navigate"],
    "deserialize": ["deserialize", "pickle.loads", "yaml.load", "JSON.parse"],
}

# Route definition patterns for popular frameworks
ROUTE_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "express": [
        re.compile(r"""(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]"""),
    ],
    "flask": [
        re.compile(r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"](?:.*methods\s*=\s*\[([^\]]+)\])?"""),
    ],
    "django": [
        re.compile(r"""path\s*\(\s*['"]([^'"]+)['"]"""),
        re.compile(r"""url\s*\(\s*r?['"]([^'"]+)['"]"""),
    ],
    "fastapi": [
        re.compile(r"""@\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"""),
    ],
    "spring": [
        re.compile(
            r"""@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]"""
        ),
    ],
}


class RouteMapping(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    handler: str = ""
    file_path: str = ""
    line_number: int = 0
    framework: str = ""


class SinkFlow(BaseModel):
    source: str = ""
    sink: str = ""
    sink_type: str = ""
    file_path: str = ""
    line_number: int = 0


class XRefResult(BaseModel):
    routes: list[RouteMapping] = Field(default_factory=list)
    sink_flows: list[SinkFlow] = Field(default_factory=list)
    dependencies: list[dict[str, str]] = Field(default_factory=list)


class CodebaseXRef:
    """Cross-references runtime endpoints with source code."""

    # File extensions to scan
    CODE_EXTENSIONS = {".js", ".ts", ".py", ".java", ".go", ".rb", ".php"}

    def analyze(self, codebase_path: str | Path) -> XRefResult:
        """Analyze codebase for routes and dangerous sinks."""
        root = Path(codebase_path)
        if not root.exists():
            logger.error("Codebase path does not exist: %s", root)
            return XRefResult()

        routes = self._extract_routes(root)
        sinks = self._find_dangerous_sinks(root)
        deps = self._find_dependencies(root)

        return XRefResult(routes=routes, sink_flows=sinks, dependencies=deps)

    def _extract_routes(self, root: Path) -> list[RouteMapping]:
        """Extract route definitions using regex patterns."""
        routes: list[RouteMapping] = []

        for file_path in self._iter_code_files(root):
            try:
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue

            for framework, patterns in ROUTE_PATTERNS.items():
                for pattern in patterns:
                    for match in pattern.finditer(content):
                        groups = match.groups()
                        if framework in ("express", "fastapi"):
                            method = groups[0].upper()
                            path = groups[1]
                        elif framework == "flask":
                            path = groups[0]
                            method_str = groups[1] if len(groups) > 1 and groups[1] else "GET"
                            method = method_str.strip("'\" ").upper()
                        else:
                            path = groups[0]
                            method = "GET"

                        line_num = content[:match.start()].count("\n") + 1
                        routes.append(
                            RouteMapping(
                                path=path,
                                methods=[method],
                                file_path=str(file_path.relative_to(root)),
                                line_number=line_num,
                                framework=framework,
                            )
                        )

        return routes

    def _find_dangerous_sinks(self, root: Path) -> list[SinkFlow]:
        """Find potentially dangerous function calls."""
        sinks: list[SinkFlow] = []

        for file_path in self._iter_code_files(root):
            try:
                content = file_path.read_text(errors="ignore")
            except Exception:
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                for sink_type, sink_names in DANGEROUS_SINKS.items():
                    for sink_name in sink_names:
                        if sink_name in line:
                            sinks.append(
                                SinkFlow(
                                    sink=sink_name,
                                    sink_type=sink_type,
                                    file_path=str(file_path.relative_to(root)),
                                    line_number=line_num,
                                )
                            )

        return sinks

    def _find_dependencies(self, root: Path) -> list[dict[str, str]]:
        """Find dependency files for audit."""
        dep_files = {
            "package.json": "npm",
            "requirements.txt": "pip",
            "Pipfile.lock": "pipenv",
            "poetry.lock": "poetry",
            "go.sum": "go",
            "Gemfile.lock": "bundler",
            "pom.xml": "maven",
            "build.gradle": "gradle",
            "composer.lock": "composer",
        }

        found = []
        for name, manager in dep_files.items():
            matches = list(root.rglob(name))
            for match in matches:
                found.append({
                    "file": str(match.relative_to(root)),
                    "manager": manager,
                })
        return found

    def _iter_code_files(self, root: Path) -> list[Path]:
        """Iterate over code files, skipping common non-code dirs."""
        skip_dirs = {"node_modules", ".git", "__pycache__", "vendor", "dist", "build", ".venv"}
        files = []
        for path in root.rglob("*"):
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.is_file() and path.suffix in self.CODE_EXTENSIONS:
                files.append(path)
        return files
