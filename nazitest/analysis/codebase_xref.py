"""Codebase cross-reference — tree-sitter AST route extraction and sink detection."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Extension -> tree-sitter language name
EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}

# Dangerous sinks — only match actual function calls via AST
DANGEROUS_SINKS: dict[str, set[str]] = {
    "sql": {"execute", "raw", "query", "cursor", "executeQuery", "mysqli_query"},
    "command": {"exec", "spawn", "system", "popen", "subprocess.run"},
    "file": {"readFile", "writeFile", "open", "fopen", "file_get_contents"},
    "template": {"render", "render_template", "eval"},
    "redirect": {"redirect", "location.replace"},
    "deserialize": {"pickle.loads", "yaml.load", "unserialize"},
}

# Flatten for quick lookup
_ALL_SINK_NAMES: set[str] = set()
for _names in DANGEROUS_SINKS.values():
    _ALL_SINK_NAMES.update(_names)

# Auth decorators / middleware patterns
AUTH_PATTERNS: set[str] = {
    "login_required", "jwt_required", "auth_required",
    "permission_required", "requires_auth", "authenticated",
    "authorize", "protect", "csrf_protect",
}

# Dirs to skip
SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "vendor", "dist", "build",
    ".venv", ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
})

# Priority dirs for route/controller discovery
PRIORITY_DIRS = frozenset({
    "routes", "controllers", "views", "handlers", "api",
    "src", "app", "lib", "models", "services",
})

# Dirs to deprioritize
DEPRIORITY_DIRS = frozenset({
    "test", "tests", "spec", "specs", "docs",
    "documentation", "examples", "fixtures",
})

MAX_PRIORITY_FILES = 500
MAX_OTHER_FILES = 1500
MAX_FILE_SIZE = 512 * 1024  # 512KB

# Regex fallbacks for route patterns
REGEX_ROUTE_PATTERNS: dict[str, list[re.Pattern[str]]] = {
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
    "laravel": [
        re.compile(r"""Route::(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"""),
    ],
    "rails": [
        re.compile(r"""\b(get|post|put|patch|delete|resources?)\s+['"]([^'"]+)['"]"""),
    ],
    "gin": [
        re.compile(r"""(?:router|r)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*['"]([^'"]+)['"]"""),
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
    auth_patterns: list[dict[str, str]] = Field(default_factory=list)
    languages_detected: list[str] = Field(default_factory=list)


class CodebaseXRef:
    """Cross-references runtime endpoints with source code using tree-sitter AST."""

    CODE_EXTENSIONS = set(EXT_TO_LANG.keys())

    def __init__(self) -> None:
        self._parsers: dict[str, object] = {}

    def _get_parser(self, lang: str):  # noqa: ANN202
        """Lazily load tree-sitter parsers."""
        if lang not in self._parsers:
            try:
                from tree_sitter_language_pack import get_parser
                self._parsers[lang] = get_parser(lang)
            except Exception as e:
                logger.debug("No parser for %s: %s", lang, e)
                self._parsers[lang] = None
        return self._parsers[lang]

    def analyze(self, codebase_path: str | Path) -> XRefResult:
        """Analyze codebase for routes, dangerous sinks, and auth patterns."""
        root = Path(codebase_path)
        if not root.exists():
            logger.error("Codebase path does not exist: %s", root)
            return XRefResult()

        files = self._collect_files(root)
        languages_detected: set[str] = set()

        routes: list[RouteMapping] = []
        sinks: list[SinkFlow] = []
        auth_patterns: list[dict[str, str]] = []

        for file_path in files:
            lang = EXT_TO_LANG.get(file_path.suffix)
            if not lang:
                continue
            languages_detected.add(lang)

            try:
                content = file_path.read_bytes()
                if len(content) > MAX_FILE_SIZE:
                    continue
            except Exception:
                continue

            rel_path = str(file_path.relative_to(root))
            text = content.decode("utf-8", errors="ignore")

            parser = self._get_parser(lang)
            if parser is not None:
                try:
                    tree = parser.parse(content)
                    root_node = tree.root_node
                    routes.extend(self._ast_extract_routes(root_node, text, rel_path, lang))
                    sinks.extend(self._ast_find_sinks(root_node, text, rel_path))
                    auth_patterns.extend(self._ast_find_auth(root_node, text, rel_path, lang))
                    continue
                except Exception as e:
                    logger.debug("AST parse failed for %s, using regex: %s", rel_path, e)

            # Regex fallback
            routes.extend(self._regex_extract_routes(text, rel_path))
            sinks.extend(self._regex_find_sinks(text, rel_path))

        deps = self._find_dependencies(root)

        return XRefResult(
            routes=routes,
            sink_flows=sinks,
            dependencies=deps,
            auth_patterns=auth_patterns,
            languages_detected=sorted(languages_detected),
        )

    # ── AST-based extraction ──

    def _ast_extract_routes(
        self, root_node, text: str, rel_path: str, lang: str,
    ) -> list[RouteMapping]:
        """Walk AST to find route definitions per language."""
        routes: list[RouteMapping] = []

        if lang == "python":
            routes.extend(self._ast_routes_python(root_node, text, rel_path))
        elif lang in ("javascript", "typescript"):
            routes.extend(self._ast_routes_js(root_node, text, rel_path))
        elif lang == "java":
            routes.extend(self._ast_routes_java(root_node, text, rel_path))
        elif lang == "go":
            routes.extend(self._ast_routes_go(root_node, text, rel_path))
        elif lang == "ruby":
            routes.extend(self._ast_routes_ruby(root_node, text, rel_path))
        elif lang == "php":
            routes.extend(self._ast_routes_php(root_node, text, rel_path))

        return routes

    def _ast_routes_python(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Flask/FastAPI/Django routes from Python AST."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "decorator":
                        dec_text = text[child.start_byte:child.end_byte]
                        # Flask: @app.route('/path', methods=['GET'])
                        m = re.match(
                            r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"]"
                            r"(?:.*methods\s*=\s*\[([^\]]+)\])?",
                            dec_text,
                        )
                        if m:
                            path = m.group(1)
                            methods_str = m.group(2) or "GET"
                            methods = [
                                s.strip().strip("'\"").upper()
                                for s in methods_str.split(",")
                            ]
                            handler = self._get_func_name(node, text)
                            routes.append(RouteMapping(
                                path=path, methods=methods, handler=handler,
                                file_path=rel_path, line_number=node.start_point[0] + 1,
                                framework="flask",
                            ))
                            continue

                        # FastAPI: @app.get('/path'), @router.post('/path')
                        m = re.match(
                            r"@\w+\.(get|post|put|delete|patch|options|head)"
                            r"\s*\(\s*['\"]([^'\"]+)['\"]",
                            dec_text,
                        )
                        if m:
                            method = m.group(1).upper()
                            path = m.group(2)
                            handler = self._get_func_name(node, text)
                            routes.append(RouteMapping(
                                path=path, methods=[method], handler=handler,
                                file_path=rel_path, line_number=node.start_point[0] + 1,
                                framework="fastapi",
                            ))
        return routes

    def _ast_routes_js(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Express/Koa routes from JS/TS AST."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type == "call_expression":
                func_text = ""
                if node.child_count > 0:
                    func_node = node.children[0]
                    func_text = text[func_node.start_byte:func_node.end_byte]

                # app.get('/path', handler) or router.post('/path', handler)
                m = re.match(
                    r"(?:app|router|server)\.(get|post|put|delete|patch|all|use)",
                    func_text,
                )
                if m:
                    method = m.group(1).upper()
                    if method == "USE":
                        method = "ALL"
                    # Find first string argument
                    args_node = node.child_by_field_name("arguments")
                    if args_node:
                        for arg in args_node.children:
                            if arg.type in ("string", "template_string"):
                                path = text[arg.start_byte:arg.end_byte].strip("'\"`")
                                if path.startswith("/"):
                                    routes.append(RouteMapping(
                                        path=path, methods=[method],
                                        file_path=rel_path,
                                        line_number=node.start_point[0] + 1,
                                        framework="express",
                                    ))
                                break
        return routes

    def _ast_routes_java(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Spring routes from Java AST."""
        routes: list[RouteMapping] = []
        mapping_methods = {
            "GetMapping": "GET", "PostMapping": "POST",
            "PutMapping": "PUT", "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH", "RequestMapping": "GET",
        }
        for node in self._walk(root_node):
            if node.type in ("marker_annotation", "annotation"):
                ann_text = text[node.start_byte:node.end_byte]
                for ann_name, method in mapping_methods.items():
                    if ann_name in ann_text:
                        m = re.search(r"""['\"]([^'"]+)['\"]""", ann_text)
                        if m:
                            path = m.group(1)
                            routes.append(RouteMapping(
                                path=path, methods=[method],
                                file_path=rel_path,
                                line_number=node.start_point[0] + 1,
                                framework="spring",
                            ))
                        break
        return routes

    def _ast_routes_go(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Go net/http, Gin, Echo routes."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type == "call_expression":
                func_text = ""
                if node.child_count > 0:
                    func_node = node.children[0]
                    func_text = text[func_node.start_byte:func_node.end_byte]

                # http.HandleFunc("/path", handler)
                if "HandleFunc" in func_text or "Handle" in func_text:
                    path = self._extract_first_string_arg(node, text)
                    if path and path.startswith("/"):
                        routes.append(RouteMapping(
                            path=path, methods=["GET"],
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                            framework="net/http",
                        ))

                # router.GET("/path", handler)
                m = re.match(
                    r"(?:router|r|e|g)\.(GET|POST|PUT|DELETE|PATCH)",
                    func_text,
                )
                if m:
                    method = m.group(1)
                    path = self._extract_first_string_arg(node, text)
                    if path and path.startswith("/"):
                        routes.append(RouteMapping(
                            path=path, methods=[method],
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                            framework="gin",
                        ))
        return routes

    def _ast_routes_ruby(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Rails routes from Ruby AST."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type == "call":
                func_text = text[node.start_byte:node.end_byte]
                m = re.match(
                    r"\b(get|post|put|patch|delete|resources?)\s+['\"]([^'\"]+)['\"]",
                    func_text,
                )
                if m:
                    method = m.group(1).upper()
                    path = m.group(2)
                    if method.startswith("RESOURCE"):
                        method = "GET"
                    if not path.startswith("/"):
                        path = "/" + path
                    routes.append(RouteMapping(
                        path=path, methods=[method],
                        file_path=rel_path,
                        line_number=node.start_point[0] + 1,
                        framework="rails",
                    ))
        return routes

    def _ast_routes_php(self, root_node, text: str, rel_path: str) -> list[RouteMapping]:
        """Extract Laravel routes from PHP AST."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type in ("function_call_expression", "member_call_expression",
                             "scoped_call_expression"):
                call_text = text[node.start_byte:node.end_byte]
                m = re.match(
                    r"Route::(get|post|put|delete|patch|any)\s*\(\s*['\"]([^'\"]+)['\"]",
                    call_text,
                )
                if m:
                    method = m.group(1).upper()
                    path = m.group(2)
                    routes.append(RouteMapping(
                        path=path, methods=[method],
                        file_path=rel_path,
                        line_number=node.start_point[0] + 1,
                        framework="laravel",
                    ))
        return routes

    def _ast_find_sinks(self, root_node, text: str, rel_path: str) -> list[SinkFlow]:
        """Walk call nodes and match against dangerous sink names."""
        sinks: list[SinkFlow] = []
        for node in self._walk(root_node):
            if node.type not in (
                "call", "call_expression", "function_call_expression",
                "member_call_expression", "scoped_call_expression",
                "method_invocation",
            ):
                continue

            # Get the callee name
            callee = self._get_callee_name(node, text)
            if not callee:
                continue

            # Check against all sinks
            for sink_type, sink_names in DANGEROUS_SINKS.items():
                for sink_name in sink_names:
                    # Match the full name or just the method part
                    if callee == sink_name or callee.endswith("." + sink_name):
                        sinks.append(SinkFlow(
                            sink=callee,
                            sink_type=sink_type,
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                        ))
                        break
                else:
                    continue
                break

        return sinks

    def _ast_find_auth(
        self, root_node, text: str, rel_path: str, lang: str,
    ) -> list[dict[str, str]]:
        """Detect auth decorators and middleware patterns."""
        patterns: list[dict[str, str]] = []

        if lang == "python":
            for node in self._walk(root_node):
                if node.type == "decorator":
                    dec_text = text[node.start_byte:node.end_byte].lstrip("@")
                    for auth_name in AUTH_PATTERNS:
                        if auth_name in dec_text:
                            patterns.append({
                                "type": "decorator_auth",
                                "name": auth_name,
                                "file_path": rel_path,
                                "line_number": str(node.start_point[0] + 1),
                            })
                            break
        elif lang in ("javascript", "typescript"):
            for node in self._walk(root_node):
                if node.type in ("call_expression", "identifier"):
                    node_text = text[node.start_byte:node.end_byte]
                    for auth_name in AUTH_PATTERNS:
                        if auth_name in node_text:
                            patterns.append({
                                "type": "middleware_auth",
                                "name": auth_name,
                                "file_path": rel_path,
                                "line_number": str(node.start_point[0] + 1),
                            })
                            break
        elif lang == "java":
            for node in self._walk(root_node):
                if node.type in ("marker_annotation", "annotation"):
                    ann_text = text[node.start_byte:node.end_byte]
                    for auth_name in AUTH_PATTERNS:
                        if auth_name in ann_text.lower():
                            patterns.append({
                                "type": "annotation_auth",
                                "name": auth_name,
                                "file_path": rel_path,
                                "line_number": str(node.start_point[0] + 1),
                            })
                            break

        return patterns

    # ── Regex fallbacks ──

    def _regex_extract_routes(self, text: str, rel_path: str) -> list[RouteMapping]:
        """Fallback regex route extraction."""
        routes: list[RouteMapping] = []
        for framework, patterns in REGEX_ROUTE_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    groups = match.groups()
                    if framework in ("express", "fastapi", "laravel", "gin"):
                        method = groups[0].upper()
                        path = groups[1]
                    elif framework == "flask":
                        path = groups[0]
                        method_str = groups[1] if len(groups) > 1 and groups[1] else "GET"
                        method = method_str.strip("'\" ").upper()
                    elif framework == "rails":
                        method = groups[0].upper()
                        if method.startswith("RESOURCE"):
                            method = "GET"
                        path = groups[1]
                    else:
                        path = groups[0]
                        method = "GET"

                    line_num = text[:match.start()].count("\n") + 1
                    routes.append(RouteMapping(
                        path=path, methods=[method], file_path=rel_path,
                        line_number=line_num, framework=framework,
                    ))
        return routes

    def _regex_find_sinks(self, text: str, rel_path: str) -> list[SinkFlow]:
        """Fallback regex sink detection (substring matching)."""
        sinks: list[SinkFlow] = []
        for line_num, line in enumerate(text.splitlines(), 1):
            # Skip comments and strings-only lines
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue
            for sink_type, sink_names in DANGEROUS_SINKS.items():
                for sink_name in sink_names:
                    if sink_name in line:
                        sinks.append(SinkFlow(
                            sink=sink_name, sink_type=sink_type,
                            file_path=rel_path, line_number=line_num,
                        ))
        return sinks

    # ── Helpers ──

    @staticmethod
    def _walk(node):  # noqa: ANN205
        """Depth-first walk of all AST nodes."""
        yield node
        for child in node.children:
            yield from CodebaseXRef._walk(child)

    @staticmethod
    def _get_func_name(decorated_def_node, text: str) -> str:
        """Get the function name from a decorated_definition node."""
        for child in decorated_def_node.children:
            if child.type in ("function_definition", "async_function_definition"):
                name_node = child.child_by_field_name("name")
                if name_node:
                    return text[name_node.start_byte:name_node.end_byte]
        return ""

    @staticmethod
    def _get_callee_name(call_node, text: str) -> str:
        """Extract the function/method name from a call node."""
        if call_node.child_count == 0:
            return ""
        func_node = call_node.children[0]
        # For attribute access like obj.method(), get the full dotted name
        callee = text[func_node.start_byte:func_node.end_byte]
        # Trim to just the last method call for cleanliness
        # but keep one dot for context (e.g., cursor.execute)
        parts = callee.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return callee

    @staticmethod
    def _extract_first_string_arg(call_node, text: str) -> str:
        """Extract the first string literal argument from a call node."""
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            # Try the second child (argument_list)
            for child in call_node.children:
                if child.type == "argument_list":
                    args_node = child
                    break
        if args_node is None:
            return ""
        for child in args_node.children:
            if child.type in ("interpreted_string_literal", "raw_string_literal",
                              "string", "string_literal"):
                return text[child.start_byte:child.end_byte].strip("'\"`")
        return ""

    def _collect_files(self, root: Path) -> list[Path]:
        """Collect code files with priority ordering and limits."""
        priority_files: list[Path] = []
        other_files: list[Path] = []

        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix not in self.CODE_EXTENSIONS:
                continue

            is_priority = any(part in PRIORITY_DIRS for part in path.parts)
            is_depriority = any(part in DEPRIORITY_DIRS for part in path.parts)

            if is_depriority:
                continue
            elif is_priority:
                if len(priority_files) < MAX_PRIORITY_FILES:
                    priority_files.append(path)
            else:
                if len(other_files) < MAX_OTHER_FILES:
                    other_files.append(path)

        return priority_files + other_files

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
                if any(part in SKIP_DIRS for part in match.parts):
                    continue
                found.append({
                    "file": str(match.relative_to(root)),
                    "manager": manager,
                })
        return found
