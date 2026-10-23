"""Stage only public Manager assets, independently of core wheel resources."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory

# This repository-owned module uses stdlib only until its HTTP view is called.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "manager"))
from accounts.shell import checked_path, validate_public_build


def stage_manager_ui(build_root, static_root):
    html, assets = validate_public_build(build_root)
    source, target = checked_path(build_root), checked_path(static_root)
    if source.is_relative_to(target) or target.is_relative_to(source):
        raise ValueError("manager_ui_unavailable")
    destination = checked_path(target / "manager")
    if destination.exists():
        # Only replace a stage owned by this command, never a private directory.
        marker = checked_path(destination / "manifest.json")
        manifest = json.loads(marker.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "1.0" or not isinstance(manifest.get("sha256"), dict):
            raise ValueError("manager_ui_unavailable")
        for path in destination.rglob("*"):
            checked_path(path)
    # Read and hash all validated assets before touching the public destination.
    payloads = {name: path.read_bytes() for name, path in assets.items()}
    hashes = {"manager.html": sha256(html.encode("utf-8")).hexdigest()}
    hashes.update({"assets/" + name: sha256(data).hexdigest() for name, data in payloads.items()})
    target.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".manager-stage-", dir=target) as folder:
        staged = Path(folder) / "manager"
        (staged / "assets").mkdir(parents=True)
        for name, data in payloads.items():
            (staged / "assets" / name).write_bytes(data)
        (staged / "manifest.json").write_text(json.dumps({"schema_version": "1.0", "sha256": hashes},
                                                      indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if destination.exists():
            # checked_path and overlap checks above constrain recursive removal.
            shutil.rmtree(destination)
        staged.replace(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--static-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        stage_manager_ui(args.build_root, args.static_root)
    except (OSError, ValueError, TypeError, AttributeError):
        print("manager_ui_unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
