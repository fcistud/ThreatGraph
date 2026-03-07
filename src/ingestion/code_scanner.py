"""Code Awareness Layer — parses a codebase into a SurrealDB knowledge graph.

Builds Layer 3 of the ThreatGraph knowledge graph:
- code_module nodes (files with classes/functions)
- dependency nodes (from requirements.txt, package.json, go.mod, Cargo.toml, etc.)
- imports edges (code_module → code_module)
- depends_on edges (project → dependency)
- deployed_on edges (dependency → asset via software_version)

Supports scanning local directories OR GitHub URLs (auto-clones).
Inspired by GitNexus (https://github.com/abhigyanpatwari/GitNexus).
"""

import os
import re
import json
import sys
import ast
import shutil
import subprocess
import tempfile
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database import get_db


def clone_github_repo(url: str) -> str:
    """Clone a GitHub repo to a temp directory. Returns the path."""
    # Normalize URL
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = f"https://github.com/{url}"
    if url.endswith(".git"):
        url = url[:-4]

    repo_name = url.split("/")[-1]
    tmp_dir = os.path.join(tempfile.gettempdir(), f"threatgraph_scan_{repo_name}")

    # Clean old clone if exists
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)

    print(f"  Cloning {url} → {tmp_dir}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, tmp_dir],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")

    return tmp_dir


def is_github_url(path: str) -> bool:
    """Check if a path looks like a GitHub URL."""
    return any(x in path for x in ["github.com", "gitlab.com", "bitbucket.org"])




# ─── FILE PARSERS ─────────────────────────────────────

def parse_python_file(file_path: str) -> dict:
    """Parse a Python file to extract imports, classes, functions."""
    with open(file_path, "r", errors="ignore") as f:
        source = f.read()

    result = {
        "file_path": file_path,
        "language": "python",
        "imports": [],
        "classes": [],
        "functions": [],
        "loc": source.count("\n"),
    }

    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    result["imports"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                result["imports"].append(module)
                for alias in node.names:
                    result["imports"].append(f"{module}.{alias.name}")
            elif isinstance(node, ast.ClassDef):
                result["classes"].append(node.name)
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                result["functions"].append(node.name)
    except SyntaxError:
        # Fall back to regex for files with syntax errors
        result["imports"] = re.findall(r'^(?:from\s+(\S+)\s+)?import\s+(\S+)', source, re.MULTILINE)
        result["imports"] = [i for pair in result["imports"] for i in pair if i]

    return result


def parse_javascript_file(file_path: str) -> dict:
    """Parse a JS/TS file to extract imports, classes, functions."""
    with open(file_path, "r", errors="ignore") as f:
        source = f.read()

    imports = re.findall(r"(?:import|require)\s*\(?\s*['\"](.+?)['\"]", source)
    classes = re.findall(r"class\s+(\w+)", source)
    functions = re.findall(r"(?:function|const|let|var)\s+(\w+)\s*(?:=\s*(?:async\s+)?\(|=\s*function|\()", source)

    return {
        "file_path": file_path,
        "language": "javascript",
        "imports": imports,
        "classes": classes,
        "functions": functions,
        "loc": source.count("\n"),
    }


def parse_requirements_txt(file_path: str) -> list:
    """Parse requirements.txt for Python dependencies."""
    deps = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:([><=!~]+)\s*(.+))?', line)
            if match:
                name = match.group(1)
                version = match.group(3) or "latest"
                deps.append({"name": name, "version": version, "ecosystem": "pypi"})
    return deps


def parse_package_json(file_path: str) -> list:
    """Parse package.json for Node.js dependencies."""
    deps = []
    with open(file_path, "r") as f:
        data = json.load(f)
    for section in ["dependencies", "devDependencies"]:
        for name, version in data.get(section, {}).items():
            version = re.sub(r'^[~^]', '', version)
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    return deps


PARSERS = {
    ".py": parse_python_file,
    ".js": parse_javascript_file,
    ".ts": parse_javascript_file,
    ".jsx": parse_javascript_file,
    ".tsx": parse_javascript_file,
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
             ".tox", ".eggs", "dist", "build", ".mypy_cache", ".pytest_cache"}


# ─── SCANNER ──────────────────────────────────────────

def scan_codebase(repo_path: str, max_files: int = 200) -> dict:
    """Scan a codebase and extract structure information."""
    modules = []
    dependencies = []
    file_count = 0

    repo_name = os.path.basename(os.path.abspath(repo_path))

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            if file_count >= max_files:
                break

            ext = os.path.splitext(fname)[1].lower()
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, repo_path)

            # Parse source files
            if ext in PARSERS:
                try:
                    info = PARSERS[ext](full_path)
                    info["file_path"] = rel_path
                    info["repo"] = repo_name
                    modules.append(info)
                    file_count += 1
                except Exception:
                    pass

            # Parse dependency files
            if fname == "requirements.txt":
                dependencies.extend(parse_requirements_txt(full_path))
            elif fname == "package.json":
                dependencies.extend(parse_package_json(full_path))

    return {
        "repo": repo_name,
        "modules": modules,
        "dependencies": dependencies,
        "total_files": file_count,
        "total_loc": sum(m.get("loc", 0) for m in modules),
    }


# ─── SURREAL INGESTION ───────────────────────────────

def ingest_codebase(db, repo_path: str, max_files: int = 200):
    """Scan a codebase and load its graph into SurrealDB Layer 3."""
    print(f"── Scanning codebase: {repo_path} ──")
    scan = scan_codebase(repo_path, max_files)

    print(f"  Files: {scan['total_files']}, LOC: {scan['total_loc']}, Deps: {len(scan['dependencies'])}")

    module_ids = {}
    module_count = 0
    dep_count = 0
    import_count = 0
    dep_link_count = 0

    # 1. Create code_module nodes
    for mod in scan["modules"]:
        safe_id = mod["file_path"].replace("/", "_").replace(".", "_").replace("-", "_")[:60]
        try:
            db.query(f"CREATE code_module:⟨{safe_id}⟩ CONTENT $data;", {"data": {
                "file_path": mod["file_path"],
                "language": mod["language"],
                "repo": mod["repo"],
            }})
            module_ids[mod["file_path"]] = f"code_module:⟨{safe_id}⟩"
            module_count += 1
        except Exception:
            module_ids[mod["file_path"]] = f"code_module:⟨{safe_id}⟩"

    # 2. Create dependency nodes
    dep_ids = {}
    for dep in scan["dependencies"]:
        safe_dep = f"{dep['name']}_{dep['version']}".replace(".", "_").replace("-", "_").replace("/","_")[:60]
        try:
            db.query(f"CREATE dependency:⟨{safe_dep}⟩ CONTENT $data;", {"data": {
                "name": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
            }})
            dep_ids[dep["name"]] = f"dependency:⟨{safe_dep}⟩"
            dep_count += 1
        except Exception:
            dep_ids[dep["name"]] = f"dependency:⟨{safe_dep}⟩"

    # 3. Create import edges (code_module → code_module)
    for mod in scan["modules"]:
        src_id = module_ids.get(mod["file_path"])
        if not src_id:
            continue
        for imp in mod.get("imports", []):
            # Try to find matching module
            for other_path, other_id in module_ids.items():
                if other_path == mod["file_path"]:
                    continue
                # Match by module name (e.g., "src.config" matches "src/config.py")
                mod_path_as_import = other_path.replace("/", ".").replace(".py", "")
                if imp == mod_path_as_import or imp.startswith(mod_path_as_import + "."):
                    try:
                        db.query(f"RELATE {src_id}->imports->{other_id};")
                        import_count += 1
                    except Exception:
                        pass
                    break

    # 4. Create depends_on edges (code_module → dependency)
    for mod in scan["modules"]:
        src_id = module_ids.get(mod["file_path"])
        if not src_id:
            continue
        for imp in mod.get("imports", []):
            # Match top-level import to dependency
            top_level = imp.split(".")[0].replace("_", "-")
            dep_id = dep_ids.get(top_level) or dep_ids.get(imp.split(".")[0])
            if dep_id:
                try:
                    db.query(f"RELATE {src_id}->depends_on->{dep_id};")
                    dep_link_count += 1
                except Exception:
                    pass

    # 5. Link dependencies to software_versions (cross-layer connection!)
    sw_results = db.query("SELECT * FROM software_version;")
    sw_map = {}
    if isinstance(sw_results, list):
        for item in sw_results:
            if isinstance(item, list):
                for sw in item:
                    sw_map[sw.get("name", "").lower()] = str(sw.get("id", ""))
            elif isinstance(item, dict):
                sw_map[item.get("name", "").lower()] = str(item.get("id", ""))

    for dep_name, dep_id in dep_ids.items():
        # Check if dependency name matches any software_version
        dep_lower = dep_name.lower()
        for sw_name, sw_id in sw_map.items():
            if dep_lower in sw_name.lower() or sw_name.lower() in dep_lower:
                try:
                    db.query(f"RELATE {dep_id}->deployed_on->{sw_id};")
                except Exception:
                    pass

    print(f"  Modules: {module_count}, Dependencies: {dep_count}")
    print(f"  Import edges: {import_count}, Dep links: {dep_link_count}")
    return scan


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        # Default: scan the ThreatGraph repo itself
        repo = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    else:
        repo = sys.argv[1]

    db = get_db()
    result = ingest_codebase(db, repo)
    print(f"\n✓ Codebase ingested: {result['total_files']} files, {result['total_loc']} LOC")
