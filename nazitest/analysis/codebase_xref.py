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

# Sink danger ranking (higher = more dangerous, used for LLM context ordering)
SINK_DANGER_RANK: dict[str, int] = {
    "sql": 6,
    "command": 6,
    "deserialize": 5,
    "template": 4,
    "redirect": 3,
    "file": 2,
}

# Auth decorators / middleware patterns
AUTH_PATTERNS: set[str] = {
    "login_required", "jwt_required", "auth_required",
    "permission_required", "requires_auth", "authenticated",
    "authorize", "protect", "csrf_protect",
    "isAuthorized", "isAuthenticated", "dpiAware",
}

# --- FIX 1 & 2: Expanded skip dirs ---
# Dirs always skipped (not code, build artifacts, deps)
SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "vendor", "dist", "build",
    ".venv", ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
    # FIX 1: skip data/fixture/example dirs that contain non-production code
    "data", "static", "fixtures", "examples", "samples", "mock", "mocks",
    # FIX 2: skip client-side dirs (not relevant for server-side sinks)
    "frontend", "client", "public", "www", "web", "assets",
})

# Priority dirs for route/controller discovery
PRIORITY_DIRS = frozenset({
    "routes", "controllers", "views", "handlers", "api",
    "src", "app", "lib", "models", "services",
})

# Dirs to deprioritize (skip entirely)
DEPRIORITY_DIRS = frozenset({
    "test", "tests", "spec", "specs", "docs",
    "documentation",
})

# --- FIX 7: Filename patterns to skip (test/spec files co-located with source) ---
SKIP_FILE_PATTERNS = frozenset({
    ".spec.ts", ".spec.js", ".spec.tsx", ".spec.jsx",
    ".test.ts", ".test.js", ".test.tsx", ".test.jsx",
    ".spec.py", ".test.py",
    "_test.go", "_test.py",
    "Test.java", "Tests.java",
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

# Main entry-point filenames for Express/Node apps
_MAIN_APP_FILES = frozenset({
    "server.ts", "server.js", "app.ts", "app.js",
    "index.ts", "index.js", "main.ts", "main.js",
})


class RouteMapping(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    handler: str = ""
    file_path: str = ""
    line_number: int = 0
    framework: str = ""
    source_module: str = ""  # the handler's source file (for sink correlation)


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
        # FIX 3: import map built from main app file
        # Maps local identifier -> module path (relative to repo root)
        self._import_map: dict[str, str] = {}
        # FIX 3: mount map built from app.use() calls
        # Maps module path (relative) -> mount prefix
        self._mount_map: dict[str, str] = {}
        # Maps module path -> list of identifier names imported from it
        self._module_to_idents: dict[str, list[str]] = {}

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

        # FIX 3: Pre-scan main app file to build import/mount maps
        self._build_mount_maps(root)

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

        # FIX 3: Resolve mounted router paths — routes in sub-router files
        # with path "/" should get their actual mount prefix
        routes = self._resolve_mounted_routes(routes)

        # FIX 5: Annotate routes with their source module for sink correlation
        routes = self._annotate_source_modules(routes)

        deps = self._find_dependencies(root)

        # Deduplicate auth patterns
        seen_auth: set[str] = set()
        deduped_auth: list[dict[str, str]] = []
        for a in auth_patterns:
            key = f"{a['name']}:{a['file_path']}:{a['line_number']}"
            if key not in seen_auth:
                seen_auth.add(key)
                deduped_auth.append(a)

        return XRefResult(
            routes=routes,
            sink_flows=sinks,
            dependencies=deps,
            auth_patterns=deduped_auth,
            languages_detected=sorted(languages_detected),
        )

    # ── FIX 3: Mount map building ──

    def _build_mount_maps(self, root: Path) -> None:
        """Pre-scan the main app file to build import and mount maps.

        Parses import/require statements to map identifiers to module paths,
        then parses app.use('/prefix', handler) to map modules to mount prefixes.
        """
        # Find the main app file
        main_file = None
        for name in _MAIN_APP_FILES:
            candidate = root / name
            if candidate.exists():
                main_file = candidate
                break
        # Also check src/ subdirectory
        if main_file is None:
            for name in _MAIN_APP_FILES:
                candidate = root / "src" / name
                if candidate.exists():
                    main_file = candidate
                    break

        if main_file is None:
            return

        lang = EXT_TO_LANG.get(main_file.suffix)
        if not lang or lang not in ("javascript", "typescript"):
            return

        try:
            content = main_file.read_bytes()
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            return

        parser = self._get_parser(lang)
        if parser is None:
            return

        try:
            tree = parser.parse(content)
        except Exception:
            return

        rel_main = str(main_file.relative_to(root))
        main_dir = str(Path(rel_main).parent)

        # Pass 1: Build import map (identifier -> module relative path)
        for node in self._walk(tree.root_node):
            # import { searchProducts } from './routes/search'
            # import dataErasure from './routes/dataErasure'
            if node.type == "import_statement":
                module_path = ""
                idents: list[str] = []
                for child in node.children:
                    if child.type == "string":
                        module_path = text[child.start_byte:child.end_byte].strip("'\"")
                    elif child.type == "import_clause":
                        for ic in self._walk(child):
                            if ic.type == "identifier":
                                idents.append(text[ic.start_byte:ic.end_byte])
                if module_path and idents:
                    resolved = self._resolve_module_path(module_path, main_dir)
                    for ident in idents:
                        self._import_map[ident] = resolved
                    self._module_to_idents.setdefault(resolved, []).extend(idents)

            # const verify = require('./routes/verify')
            if node.type == "lexical_declaration":
                for child in node.children:
                    if child.type == "variable_declarator":
                        ident_node = child.child_by_field_name("name")
                        value_node = child.child_by_field_name("value")
                        if ident_node and value_node and value_node.type == "call_expression":
                            func_text = ""
                            if value_node.child_count > 0:
                                func_text = text[value_node.children[0].start_byte:
                                                  value_node.children[0].end_byte]
                            if func_text == "require":
                                mod_path = self._extract_first_string_arg(value_node, text)
                                if mod_path:
                                    ident = text[ident_node.start_byte:ident_node.end_byte]
                                    resolved = self._resolve_module_path(mod_path, main_dir)
                                    self._import_map[ident] = resolved
                                    self._module_to_idents.setdefault(resolved, []).append(ident)

        # Pass 2: Build mount map from app.use('/prefix', handler)
        for node in self._walk(tree.root_node):
            if node.type != "call_expression":
                continue
            if node.child_count == 0:
                continue
            func_node = node.children[0]
            func_text = text[func_node.start_byte:func_node.end_byte]

            m = re.match(r"(?:app|server)\.(use|get|post|put|delete|patch|all)", func_text)
            if not m:
                continue

            args_node = node.child_by_field_name("arguments")
            if not args_node:
                continue

            # Extract path string and handler identifiers
            path_str = ""
            handler_idents: list[str] = []
            for arg in args_node.children:
                if arg.type == "string" and not path_str:
                    raw = text[arg.start_byte:arg.end_byte].strip("'\"")
                    if raw.startswith("/"):
                        path_str = raw
                elif arg.type == "identifier":
                    handler_idents.append(text[arg.start_byte:arg.end_byte])
                elif arg.type == "call_expression":
                    # handler() — get the function name
                    if arg.child_count > 0:
                        callee = arg.children[0]
                        callee_text = text[callee.start_byte:callee.end_byte]
                        # Skip middleware like security.isAuthorized()
                        if "." not in callee_text:
                            handler_idents.append(callee_text)

            if path_str and handler_idents:
                for ident in handler_idents:
                    if ident in self._import_map:
                        self._mount_map[self._import_map[ident]] = path_str

        logger.info(
            "Mount map: %d imports, %d mounts",
            len(self._import_map), len(self._mount_map),
        )

    @staticmethod
    def _resolve_module_path(module_path: str, main_dir: str) -> str:
        """Resolve './routes/search' relative to main_dir into 'routes/search'."""
        # Strip leading ./ or ../
        clean = module_path.lstrip("./")
        if main_dir and main_dir != ".":
            return f"{main_dir}/{clean}"
        return clean

    def _resolve_mounted_routes(self, routes: list[RouteMapping]) -> list[RouteMapping]:
        """FIX 3: Prepend mount prefix to routes from sub-router files."""
        resolved: list[RouteMapping] = []
        for route in routes:
            # Check if this file has a mount prefix
            prefix = self._find_mount_prefix(route.file_path)
            if prefix and route.path == "/":
                # Router-local "/" maps to the mount point
                route = route.model_copy(update={"path": prefix})
            elif prefix and not route.path.startswith(prefix):
                # Prepend prefix to relative paths
                combined = prefix.rstrip("/") + "/" + route.path.lstrip("/")
                route = route.model_copy(update={"path": combined})
            resolved.append(route)
        return resolved

    def _find_mount_prefix(self, file_path: str) -> str:
        """Find the mount prefix for a route handler file."""
        # Try exact match first
        # file_path: "routes/dataErasure.ts" -> mount_map key: "routes/dataErasure"
        stem = str(Path(file_path).with_suffix(""))
        if stem in self._mount_map:
            return self._mount_map[stem]

        # Try without extension variants
        for mod_path, prefix in self._mount_map.items():
            if stem == mod_path or stem.endswith("/" + mod_path):
                return prefix

        return ""

    def _annotate_source_modules(self, routes: list[RouteMapping]) -> list[RouteMapping]:
        """FIX 5: For routes registered in the main app file via imported handlers,
        annotate each route with the handler's actual source file."""
        annotated: list[RouteMapping] = []
        for route in routes:
            if route.handler and route.handler in self._import_map:
                mod_path = self._import_map[route.handler]
                route = route.model_copy(update={"source_module": mod_path})
            annotated.append(route)
        return annotated

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
        """Extract Express/Koa routes from JS/TS AST. FIX 4: extracts handler names."""
        routes: list[RouteMapping] = []
        for node in self._walk(root_node):
            if node.type != "call_expression":
                continue
            if node.child_count == 0:
                continue

            func_node = node.children[0]
            func_text = text[func_node.start_byte:func_node.end_byte]

            # app.get('/path', handler) or router.post('/path', handler)
            m = re.match(
                r"(?:app|router|server)\.(get|post|put|delete|patch|all|use)",
                func_text,
            )
            if not m:
                continue

            method = m.group(1).upper()
            if method == "USE":
                method = "ALL"

            args_node = node.child_by_field_name("arguments")
            if not args_node:
                continue

            # Extract path and handler name from arguments
            path_str = ""
            handler_name = ""
            for arg in args_node.children:
                if arg.type in ("string", "template_string") and not path_str:
                    path_str = text[arg.start_byte:arg.end_byte].strip("'\"`")
                elif path_str and not handler_name:
                    # FIX 4: Extract handler name from the argument after the path
                    handler_name = self._extract_handler_name(arg, text)

            if path_str and path_str.startswith("/"):
                routes.append(RouteMapping(
                    path=path_str, methods=[method],
                    handler=handler_name,
                    file_path=rel_path,
                    line_number=node.start_point[0] + 1,
                    framework="express",
                ))
        return routes

    @staticmethod
    def _extract_handler_name(arg_node, text: str) -> str:
        """FIX 4: Extract the handler/callback function name from a route argument.

        Handles:
          - identifier: `Users` -> "Users"
          - call_expression: `searchProducts()` -> "searchProducts"
          - arrow_function: `(req, res) => {}` -> "" (anonymous)
          - member_expression: `security.isAuthorized()` -> "" (middleware, skip)
        """
        if arg_node.type == "identifier":
            return text[arg_node.start_byte:arg_node.end_byte]
        if arg_node.type == "call_expression" and arg_node.child_count > 0:
            callee = arg_node.children[0]
            callee_text = text[callee.start_byte:callee.end_byte]
            # Skip middleware calls like security.isAuthorized()
            if "." not in callee_text:
                return callee_text
        # arrow_function and other types -> anonymous handler
        return ""

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

                if "HandleFunc" in func_text or "Handle" in func_text:
                    path = self._extract_first_string_arg(node, text)
                    if path and path.startswith("/"):
                        routes.append(RouteMapping(
                            path=path, methods=["GET"],
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                            framework="net/http",
                        ))

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

            callee = self._get_callee_name(node, text)
            if not callee:
                continue

            for sink_type, sink_names in DANGEROUS_SINKS.items():
                for sink_name in sink_names:
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
            # Only match call_expression nodes, not bare identifiers
            # to avoid matching variable names or comments
            for node in self._walk(root_node):
                if node.type == "call_expression":
                    callee = self._get_callee_name(node, text)
                    if callee:
                        for auth_name in AUTH_PATTERNS:
                            if auth_name in callee:
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
        callee = text[func_node.start_byte:func_node.end_byte]
        parts = callee.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return callee

    @staticmethod
    def _extract_first_string_arg(call_node, text: str) -> str:
        """Extract the first string literal argument from a call node."""
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
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
        """Collect code files with priority ordering and limits.

        FIX 1: Skips data/static/fixtures/examples dirs.
        FIX 2: Skips frontend/client/public dirs.
        FIX 7: Skips test/spec files by filename pattern.
        """
        priority_files: list[Path] = []
        other_files: list[Path] = []

        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix not in self.CODE_EXTENSIONS:
                continue

            # FIX 7: Skip test/spec files by filename pattern
            if self._is_test_file(path):
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

    @staticmethod
    def _is_test_file(path: Path) -> bool:
        """FIX 7: Check if a file is a test/spec file by its name."""
        name = path.name
        for pattern in SKIP_FILE_PATTERNS:
            if name.endswith(pattern):
                return True
        return False

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
