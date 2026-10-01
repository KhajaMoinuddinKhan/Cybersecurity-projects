"""Compile and test each project in its own process to isolate src packages."""
from pathlib import Path
import subprocess
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    projects = sorted(root.glob("PROJECTS/*/*"))
    failed = []
    for project in projects:
        if not (project / "tests").is_dir():
            continue
        print(f"\n=== {project.name} ===", flush=True)
        for command in (
            [sys.executable, "-m", "compileall", "-q", "src"],
            [sys.executable, "-m", "pytest", "-q", "tests"],
        ):
            result = subprocess.run(command, cwd=project, check=False)
            if result.returncode:
                failed.append(project.name)
                break
    if failed:
        print("\nChecks failed: " + ", ".join(failed))
        return 1
    print("\nAll project checks passed. Review any reported skips above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
