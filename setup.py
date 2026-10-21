"""Setuptools resource hook; Python metadata remains in pyproject.toml."""

from pathlib import Path
import runpy

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist


class BuildWithResources(build_py):
    def run(self):
        super().run()
        if self.editable_mode:
            return
        root = Path(__file__).resolve().parent
        stage = runpy.run_path(str(root / "scripts/stage_release_resources.py"))["stage_resources"]
        stage(root, Path(self.build_lib) / "aegis_verify/resources/data")


class SourceWithResources(sdist):
    def make_release_tree(self, base_dir, files):
        root = Path(__file__).resolve().parent
        select = runpy.run_path(str(root / "scripts/stage_release_resources.py"))["release_files"]
        resources = {path.relative_to(root).as_posix() for path in select(root).values()}
        # Discard stale egg-info/manifest selections of data directories first.
        prefixes = ("scenarios/", "tests/fixtures/", "frontend/dist/")
        code_files = {name for name in files if not name.replace("\\", "/").startswith(prefixes)}
        super().make_release_tree(base_dir, sorted(code_files | resources))


setup(cmdclass={"build_py": BuildWithResources, "sdist": SourceWithResources})
