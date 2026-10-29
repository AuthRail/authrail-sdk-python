"""Test built distributions from independent environments outside the checkout."""

import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    artifacts = sorted((repository / "dist").glob("*.whl")) + sorted(
        (repository / "dist").glob("*.tar.gz")
    )
    if len(artifacts) != 2:
        raise SystemExit("Build into a clean dist directory: expected one wheel and one sdist.")
    for artifact in artifacts:
        with tempfile.TemporaryDirectory(prefix="authrail-package-") as directory:
            work = Path(directory)
            environment = work / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            executable = environment / (
                "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
            )
            subprocess.run(
                [str(executable), "-m", "pip", "install", str(artifact)], check=True, cwd=work
            )
            # The source tree must not satisfy imports when testing a wheel or sdist.
            shutil.copytree(repository / "tests", work / "tests")
            subprocess.run(
                [str(executable), "-I", "-m", "unittest", "discover", "-s", "tests", "-v"],
                check=True,
                cwd=work,
            )
            subprocess.run(
                [
                    str(executable), "-I", "-c",
                    "import authrail; from pathlib import Path; "
                    "assert Path(authrail.__file__).with_name('py.typed').is_file(); "
                    "assert all(hasattr(authrail, name) for name in authrail.__all__)",
                ],
                check=True,
                cwd=work,
            )
            print(f"Installed distribution passed: {artifact.name}", flush=True)


if __name__ == "__main__":
    main()
