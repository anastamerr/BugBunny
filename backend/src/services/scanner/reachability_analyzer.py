from __future__ import annotations

import ast
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ReachabilityResult:
    is_reachable: bool
    reachability_score: float  # 0.0 to 1.0
    entry_points: List[str]  # List of entry point names that reach this code
    call_path: List[str]  # Call chain from entry point to vulnerable code
    reason: str  # Human-readable explanation


@dataclass
class CallGraphNode:
    name: str
    file_path: str
    line_start: int
    calls: Set[str] = field(default_factory=set)
    called_by: Set[str] = field(default_factory=set)
    is_entry_point: bool = False
    entry_point_type: Optional[str] = None  # 'route', 'handler', 'main', 'export'


class ReachabilityAnalyzer:
    """Analyzes code reachability from entry points to vulnerable code."""

    # Entry point patterns for different frameworks
    PYTHON_ENTRY_PATTERNS = [
        # FastAPI/Starlette
        (r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(', 'route'),
        (r'@(?:api_router|router)\.(get|post|put|delete|patch|options|head)\s*\(', 'route'),
        # Flask
        (r'@(?:app|blueprint|bp)\.(route|get|post|put|delete|patch)\s*\(', 'route'),
        # Django
        (r'def\s+(get|post|put|delete|patch|head|options)\s*\(\s*self\s*,\s*request', 'handler'),
        (r'class\s+\w+\s*\(\s*(?:View|APIView|GenericAPIView|ViewSet)', 'handler'),
        # Celery tasks
        (r'@(?:app|celery)\.(task|shared_task)\s*\(', 'task'),
        # AWS Lambda
        (r'def\s+lambda_handler\s*\(', 'handler'),
        (r'def\s+handler\s*\(\s*event\s*,\s*context', 'handler'),
        # Main entry
        (r'if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:', 'main'),
        # Click/Typer CLI
        (r'@(?:click\.command|app\.command|typer\.command)\s*\(', 'cli'),
    ]

    JS_TS_ENTRY_PATTERNS = [
        # Express.js
        (r'(?:app|router)\.(get|post|put|delete|patch|use)\s*\(', 'route'),
        # Next.js API routes
        (r'export\s+(?:default\s+)?(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|handler)', 'handler'),
        # NestJS
        (r'@(Get|Post|Put|Delete|Patch)\s*\(', 'route'),
        # AWS Lambda
        (r'exports\.handler\s*=', 'handler'),
        (r'export\s+(?:const|async\s+function)\s+handler', 'handler'),
        # Main/index exports
        (r'module\.exports\s*=', 'export'),
        (r'export\s+(?:default|{)', 'export'),
    ]

    GO_ENTRY_PATTERNS = [
        # HTTP handlers
        (r'func\s+\w+\s*\(\s*w\s+http\.ResponseWriter', 'handler'),
        (r'http\.HandleFunc\s*\(', 'route'),
        (r'r\.(?:Get|Post|Put|Delete|Patch|Handle)\s*\(', 'route'),  # chi, gorilla
        # Main function
        (r'func\s+main\s*\(\s*\)', 'main'),
    ]

    def __init__(self) -> None:
        self.call_graph: Dict[str, CallGraphNode] = {}
        self.entry_points: Set[str] = set()
        self._file_cache: Dict[str, str] = {}
        self._built_repo_root: Optional[str] = None
        self._name_index: Dict[str, Set[str]] = {}
        self._has_edges: bool = False

    def analyze(
        self,
        repo_path: Path,
        file_path: str,
        function_name: Optional[str],
        class_name: Optional[str],
        line_number: int,
    ) -> ReachabilityResult:
        """Analyze if the vulnerable code is reachable from entry points."""
        try:
            self._ensure_call_graph(repo_path)

            if not self.call_graph:
                return ReachabilityResult(
                    is_reachable=True,
                    reachability_score=0.6,
                    entry_points=[],
                    call_path=[],
                    reason="No functions detected; reachability unknown.",
                )

            if not self.entry_points:
                return ReachabilityResult(
                    is_reachable=True,
                    reachability_score=0.6,
                    entry_points=[],
                    call_path=[],
                    reason="No entry points detected; reachability unknown.",
                )

            if not self._has_edges:
                return ReachabilityResult(
                    is_reachable=True,
                    reachability_score=0.6,
                    entry_points=[],
                    call_path=[],
                    reason="No call edges detected; reachability unknown.",
                )

            # Find the target node
            target_nodes = self._select_target_nodes(
                file_path=file_path,
                function_name=function_name,
                class_name=class_name,
                line_number=line_number,
            )
            if not target_nodes:
                return ReachabilityResult(
                    is_reachable=True,
                    reachability_score=0.5,
                    entry_points=[],
                    call_path=[],
                    reason="Target function not found in call graph; reachability unknown.",
                )

            # Try to find reachability
            reachable_from, call_path, has_inbound = self._find_reachability(target_nodes)

            if reachable_from:
                return ReachabilityResult(
                    is_reachable=True,
                    reachability_score=1.0,
                    entry_points=list(reachable_from),
                    call_path=call_path,
                    reason=f"Reachable from {len(reachable_from)} entry point(s): {', '.join(list(reachable_from)[:3])}",
                )
            else:
                ext = Path(file_path).suffix.lower()
                if ext in {".js", ".jsx", ".ts", ".tsx", ".go"}:
                    return ReachabilityResult(
                        is_reachable=True,
                        reachability_score=0.5,
                        entry_points=[],
                        call_path=[],
                        reason=(
                            f"Reachability heuristic for {ext} is limited; treating as unknown."
                        ),
                    )
                if not has_inbound:
                    return ReachabilityResult(
                        is_reachable=True,
                        reachability_score=0.5,
                        entry_points=[],
                        call_path=[],
                        reason="No callers found for target; reachability unknown.",
                    )
                return ReachabilityResult(
                    is_reachable=False,
                    reachability_score=0.2,
                    entry_points=[],
                    call_path=[],
                    reason="No call path found from entry points; likely dead code or internal utility.",
                )

        except Exception as e:
            logger.warning("Reachability analysis failed: %s", str(e))
            return ReachabilityResult(
                is_reachable=True,
                reachability_score=0.5,
                entry_points=[],
                call_path=[],
                reason=f"Analysis inconclusive: {str(e)}",
            )

    def _build_call_graph(self, repo_path: Path) -> None:
        """Build a call graph for the repository."""
        self.call_graph.clear()
        self.entry_points.clear()
        self._file_cache.clear()
        self._name_index.clear()
        self._has_edges = False

        # Process Python files
        for py_file in repo_path.rglob("*.py"):
            if self._should_skip_file(py_file):
                continue
            self._analyze_python_file(repo_path, py_file)

        # Process JavaScript/TypeScript files
        for pattern in ["*.js", "*.ts", "*.jsx", "*.tsx"]:
            for js_file in repo_path.rglob(pattern):
                if self._should_skip_file(js_file):
                    continue
                self._analyze_js_file(repo_path, js_file)

        # Process Go files
        for go_file in repo_path.rglob("*.go"):
            if self._should_skip_file(go_file):
                continue
            self._analyze_go_file(repo_path, go_file)

        self._built_repo_root = str(repo_path.resolve())
        self._build_name_index()
        self._has_edges = any(node.calls for node in self.call_graph.values())

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped (tests, vendor, node_modules, etc.)."""
        path_str = str(file_path).lower().replace("\\", "/")
        skip_patterns = [
            "node_modules",
            "vendor",
            ".venv",
            "venv",
            "__pycache__",
            ".git",
            "test_",
            "_test.",
            ".spec.",
            ".test.",
            "tests/",
            "__tests__/",
            "migrations/",
        ]
        return any(pattern in path_str for pattern in skip_patterns)

    def _analyze_python_file(self, repo_path: Path, file_path: Path) -> None:
        """Analyze a Python file for functions, calls, and entry points."""
        try:
            content = file_path.read_text(errors="replace")
            self._file_cache[str(file_path)] = content
            relative_path = self._normalize_path(str(file_path.relative_to(repo_path)))

            # Check for entry point patterns in raw content
            for pattern, entry_type in self.PYTHON_ENTRY_PATTERNS:
                if re.search(pattern, content):
                    # Mark functions following decorators as entry points
                    self._mark_decorated_functions_as_entry(
                        content, relative_path, pattern, entry_type
                    )

            # Parse AST for call graph
            try:
                tree = ast.parse(content)
                self._extract_python_calls(tree, relative_path)
            except SyntaxError:
                pass

        except Exception as e:
            logger.debug("Failed to analyze Python file %s: %s", file_path, e)

    def _mark_decorated_functions_as_entry(
        self, content: str, file_path: str, pattern: str, entry_type: str
    ) -> None:
        """Mark decorated functions as entry points."""
        lines = content.splitlines()
        compiled = re.compile(pattern)
        func_pattern = re.compile(r'^\s*(?:async\s+)?def\s+(\w+)\s*\(')

        i = 0
        while i < len(lines):
            if compiled.search(lines[i]):
                # Look for the function definition after the decorator
                for j in range(i + 1, min(i + 5, len(lines))):
                    match = func_pattern.match(lines[j])
                    if match:
                        func_name = match.group(1)
                        node_key = f"{file_path}::{func_name}"
                        if node_key not in self.call_graph:
                            self.call_graph[node_key] = CallGraphNode(
                                name=func_name,
                                file_path=file_path,
                                line_start=j + 1,
                            )
                        self.call_graph[node_key].is_entry_point = True
                        self.call_graph[node_key].entry_point_type = entry_type
                        self.entry_points.add(node_key)
                        break
            i += 1

    def _extract_python_calls(self, tree: ast.AST, file_path: str) -> None:
        """Extract function definitions and calls from Python AST."""
        analyzer = self

        class _CallCollector(ast.NodeVisitor):
            def __init__(self) -> None:
                self.calls: Set[str] = set()

            def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
                call_name = analyzer._get_call_name(node)
                if call_name:
                    self.calls.add(call_name)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
                for child in node.body:
                    if isinstance(
                        child,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    ):
                        continue
                    self.visit(child)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
                for child in node.body:
                    if isinstance(
                        child,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    ):
                        continue
                    self.visit(child)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
                return None

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.class_stack: List[str] = []

            def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
                self._handle_function(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
                self._handle_function(node)

            def _handle_function(
                self, node: ast.FunctionDef | ast.AsyncFunctionDef
            ) -> None:
                class_name = self.class_stack[-1] if self.class_stack else None
                full_name = f"{class_name}.{node.name}" if class_name else node.name
                node_key = f"{file_path}::{full_name}"
                if node_key not in analyzer.call_graph:
                    analyzer.call_graph[node_key] = CallGraphNode(
                        name=full_name,
                        file_path=file_path,
                        line_start=node.lineno,
                    )
                collector = _CallCollector()
                collector.visit(node)
                analyzer.call_graph[node_key].calls.update(collector.calls)
                self.generic_visit(node)

        module_key = f"{file_path}::__module__"
        if module_key not in self.call_graph:
            self.call_graph[module_key] = CallGraphNode(
                name="__module__",
                file_path=file_path,
                line_start=1,
            )
        module_calls = _CallCollector()
        module_calls.visit(tree)
        self.call_graph[module_key].calls.update(module_calls.calls)

        _Visitor().visit(tree)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return None

    def _analyze_js_file(self, repo_path: Path, file_path: Path) -> None:
        """Analyze a JavaScript/TypeScript file for entry points."""
        try:
            content = file_path.read_text(errors="replace")
            self._file_cache[str(file_path)] = content
            relative_path = self._normalize_path(str(file_path.relative_to(repo_path)))

            for pattern, entry_type in self.JS_TS_ENTRY_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Find the function name
                    line_num = content[:match.start()].count('\n') + 1
                    func_name = self._extract_js_function_name(content, match.start())
                    if func_name:
                        node_key = f"{relative_path}::{func_name}"
                        if node_key not in self.call_graph:
                            self.call_graph[node_key] = CallGraphNode(
                                name=func_name,
                                file_path=relative_path,
                                line_start=line_num,
                            )
                        self.call_graph[node_key].is_entry_point = True
                        self.call_graph[node_key].entry_point_type = entry_type
                        self.entry_points.add(node_key)

            # Extract function calls using regex (simplified)
            self._extract_js_calls(content, relative_path)

        except Exception as e:
            logger.debug("Failed to analyze JS file %s: %s", file_path, e)

    def _extract_js_function_name(self, content: str, position: int) -> Optional[str]:
        """Extract function name near a position in JS/TS code."""
        # Look for function declaration patterns near the position
        context = content[max(0, position - 100):position + 200]
        patterns = [
            r'function\s+(\w+)',
            r'(?:const|let|var)\s+(\w+)\s*=',
            r'(\w+)\s*[=:]\s*(?:async\s+)?(?:function|\()',
            r'(?:async\s+)?(\w+)\s*\(',
        ]
        for pattern in patterns:
            match = re.search(pattern, context)
            if match:
                return match.group(1)
        return None

    def _extract_js_calls(self, content: str, file_path: str) -> None:
        """Extract function calls from JavaScript/TypeScript code."""
        func_patterns = [
            re.compile(r'\bfunction\s+([A-Za-z_]\w*)\s*\('),
            re.compile(
                r'\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s+)?function\b'
            ),
            re.compile(
                r'\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'
            ),
        ]
        call_pattern = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
        js_keywords = {
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "function",
            "return",
            "new",
            "typeof",
            "await",
            "class",
            "super",
            "this",
        }

        func_defs: List[Tuple[str, int, int]] = []
        seen_defs: Set[Tuple[str, int]] = set()
        for pattern in func_patterns:
            for match in pattern.finditer(content):
                func_name = match.group(1)
                start_idx = match.start()
                if (func_name, start_idx) in seen_defs:
                    continue
                seen_defs.add((func_name, start_idx))
                line_num = content[:start_idx].count("\n") + 1
                func_defs.append((func_name, start_idx, line_num))

        func_defs.sort(key=lambda item: item[1])
        if not func_defs:
            return

        for func_name, start_idx, line_num in func_defs:
            node_key = f"{file_path}::{func_name}"
            if node_key not in self.call_graph:
                self.call_graph[node_key] = CallGraphNode(
                    name=func_name,
                    file_path=file_path,
                    line_start=line_num,
                )

        for index, (func_name, start_idx, _) in enumerate(func_defs):
            end_idx = func_defs[index + 1][1] if index + 1 < len(func_defs) else len(content)
            body = content[start_idx:end_idx]
            node_key = f"{file_path}::{func_name}"
            for match in call_pattern.finditer(body):
                call_name = match.group(1)
                if call_name in js_keywords:
                    continue
                prefix = body[max(0, match.start() - 15):match.start()]
                if re.search(r"\bfunction\s+$", prefix):
                    continue
                if re.search(r"\bclass\s+$", prefix):
                    continue
                if re.search(r"\bnew\s+$", prefix):
                    continue
                if call_name == func_name:
                    continue
                self.call_graph[node_key].calls.add(call_name)

    def _analyze_go_file(self, repo_path: Path, file_path: Path) -> None:
        """Analyze a Go file for entry points."""
        try:
            content = file_path.read_text(errors="replace")
            self._file_cache[str(file_path)] = content
            relative_path = self._normalize_path(str(file_path.relative_to(repo_path)))

            for pattern, entry_type in self.GO_ENTRY_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    # Extract function name
                    func_match = re.search(r'func\s+(\w+)', content[match.start():match.start()+100])
                    if func_match:
                        func_name = func_match.group(1)
                        node_key = f"{relative_path}::{func_name}"
                        if node_key not in self.call_graph:
                            self.call_graph[node_key] = CallGraphNode(
                                name=func_name,
                                file_path=relative_path,
                                line_start=line_num,
                            )
                        self.call_graph[node_key].is_entry_point = True
                        self.call_graph[node_key].entry_point_type = entry_type
                        self.entry_points.add(node_key)

        except Exception as e:
            logger.debug("Failed to analyze Go file %s: %s", file_path, e)

    def _make_node_key(
        self, file_path: str, function_name: Optional[str], class_name: Optional[str]
    ) -> str:
        """Create a node key for looking up in call graph."""
        file_path = self._normalize_path(file_path)
        if class_name and function_name:
            return f"{file_path}::{class_name}.{function_name}"
        elif function_name:
            return f"{file_path}::{function_name}"
        return f"{file_path}::__module__"

    def _find_reachability(
        self, target_nodes: List[str]
    ) -> Tuple[Set[str], List[str], bool]:
        """Find if target is reachable from any entry point using BFS."""
        reachable_from: Set[str] = set()
        best_path: List[str] = []

        # Build reverse call graph (who calls whom)
        reverse_graph: Dict[str, Set[str]] = {}
        for node_key, node in self.call_graph.items():
            for called in node.calls:
                called_full = called.strip()
                call_keys = {called_full, self._normalize_call_name(called_full)}
                for call_key in call_keys:
                    for other_key in self._name_index.get(call_key, set()):
                        reverse_graph.setdefault(other_key, set()).add(node_key)

        has_inbound = any(target in reverse_graph for target in target_nodes)

        # BFS from each target node to find entry points
        for target in target_nodes:
            visited: Set[str] = set()
            queue: deque[Tuple[str, List[str]]] = deque([(target, [target])])

            while queue:
                current, path = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)

                if current in self.entry_points:
                    entry_node = self.call_graph[current]
                    entry_type = entry_node.entry_point_type or "entry"
                    entry_name = f"{entry_type}:{entry_node.name}"
                    reachable_from.add(entry_name)
                    if not best_path or len(path) < len(best_path):
                        best_path = path[::-1]  # Reverse to show entry -> target

                # Add callers to queue
                if current in reverse_graph:
                    for caller in reverse_graph[current]:
                        if caller not in visited:
                            queue.append((caller, path + [caller]))

        # If the target function itself is an entry point, record that.
        target_set = set(target_nodes)
        for node_key in target_set.intersection(self.entry_points):
            node = self.call_graph[node_key]
            entry_type = node.entry_point_type or "entry"
            entry_name = f"{entry_type}:{node.name}"
            reachable_from.add(entry_name)
            if not best_path:
                best_path = [node_key]

        return reachable_from, best_path, has_inbound

    def _ensure_call_graph(self, repo_path: Path) -> None:
        repo_root = str(repo_path.resolve())
        if self._built_repo_root != repo_root:
            self._build_call_graph(repo_path)

    def _build_name_index(self) -> None:
        self._name_index.clear()
        for node_key, node in self.call_graph.items():
            for variant in self._name_variants(node.name):
                self._name_index.setdefault(variant, set()).add(node_key)

    def _name_variants(self, name: str) -> List[str]:
        short = self._normalize_call_name(name)
        if short and short != name:
            return [name, short]
        return [name]

    def _normalize_call_name(self, name: str) -> str:
        return name.split(".")[-1].strip()

    def _normalize_path(self, value: str) -> str:
        return value.replace("\\", "/")

    def _select_target_nodes(
        self,
        file_path: str,
        function_name: Optional[str],
        class_name: Optional[str],
        line_number: int,
    ) -> List[str]:
        normalized_path = self._normalize_path(file_path)
        target_key = self._make_node_key(normalized_path, function_name, class_name)
        if target_key in self.call_graph:
            return [target_key]

        candidates = [
            key
            for key, node in self.call_graph.items()
            if node.file_path == normalized_path
        ]
        if function_name:
            matches = [
                key
                for key in candidates
                if self.call_graph[key].name.split(".")[-1] == function_name
            ]
            if matches:
                candidates = matches

        if not candidates:
            return []

        if line_number:
            valid = [
                key
                for key in candidates
                if self.call_graph[key].line_start <= line_number
            ]
            if valid:
                best = max(valid, key=lambda key: self.call_graph[key].line_start)
                return [best]

        return [candidates[0]]

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the call graph."""
        return {
            "total_functions": len(self.call_graph),
            "entry_points": len(self.entry_points),
            "routes": sum(1 for k in self.entry_points
                         if self.call_graph[k].entry_point_type == "route"),
            "handlers": sum(1 for k in self.entry_points
                           if self.call_graph[k].entry_point_type == "handler"),
        }
