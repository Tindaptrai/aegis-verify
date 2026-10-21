"""Stage explicitly reviewed public resources into the wheel build directory."""

from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import re
import shutil


class _Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.paths.append(attrs["src"])
        if tag == "link" and attrs.get("rel") in ("stylesheet", "modulepreload"):
            self.paths.append(attrs["href"])
        # Test/minimal shells may omit rel; still check their local asset links.
        elif tag == "link" and attrs.get("href", "").startswith("/assets/"):
            self.paths.append(attrs["href"])


def _local(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
        raise ValueError("invalid resource path")
    path = root.joinpath(*relative.parts)
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("missing or redirected public resource")
    return path


def release_files(source_root: Path) -> dict[str, Path]:
    """One resource selection shared by wheel and source distribution builds."""
    source_root = Path(source_root).resolve()
    public = json.loads((source_root / "packaging/public-resources.json").read_bytes())
    files = {dest: _local(source_root, origin) for dest, origin in public.items()}
    static = source_root / "frontend/dist"
    if not (static / "index.html").is_file():
        raise ValueError("Missing frontend build: run npm ci and npm run build in frontend before building the wheel")
    parser = _Assets()
    parser.feed((static / "index.html").read_text(encoding="utf-8"))
    if not parser.paths:
        raise ValueError("frontend build has no assets")
    files["static/index.html"] = _local(static, "index.html")
    for asset in parser.paths:
        if not re.fullmatch(r"/assets/[A-Za-z0-9._-]+\.(?:js|css)", asset):
            raise ValueError("invalid frontend asset path")
        files["static" + asset] = _local(static, asset.lstrip("/"))
    return files


def stage_resources(source_root: Path, target: Path) -> None:
    """Copy exact bytes; unknown files in fixture/build directories never ship."""
    source_root, target = Path(source_root).resolve(), Path(target).absolute()
    if target.is_symlink() or target.resolve() == source_root or source_root.is_relative_to(target.resolve()):
        raise ValueError("unsafe resource destination")
    files = release_files(source_root)
    # This is a generated build directory, never a user report/output directory.
    if target.exists():
        if not (target / "bundle.json").is_file():
            raise ValueError("refusing to replace an unowned resource destination")
        shutil.rmtree(target)
    target.mkdir(parents=True)
    hashes = {}
    for dest, origin in sorted(files.items()):
        relative = PurePosixPath(dest)
        if relative.is_absolute() or ".." in relative.parts or "\\" in dest or ":" in dest:
            raise ValueError("invalid resource destination")
        path = target.joinpath(*relative.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, path)
        hashes[dest] = sha256(path.read_bytes()).hexdigest()
    (target / "bundle.json").write_text(json.dumps({
        "schema_version": "1.0", "scope": "public offline demonstration; no live execution",
        "sha256": hashes,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
