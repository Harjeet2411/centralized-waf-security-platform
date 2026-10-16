"""Build one deployment zip per Lambda + stage the state machine definition.

    python build.py                    # all functions -> dist/
    python build.py account_collector  # one function
    python build.py --skip-deps        # code only (tests / quick iteration)

Each zip = <function package>/ + common/ + Linux x86_64 wheels of the runtime dependencies (psycopg[binary],
redis), installed with `pip --platform manylinux2014_x86_64 --only-binary=:all:` so a Windows/macOS build host
produces Lambda-compatible binaries. boto3 comes from the python3.12 runtime and is not bundled.
Upload dist/ to s3://<ArtifactBucket>/<ArtifactPrefix> (platform.yaml parameters).
"""

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ASL = ROOT.parent / "infra" / "central_account" / "step_functions.asl.json"
FUNCTIONS = [
    "fetch_accounts", "account_collector", "mark_account_degraded", "s3_log_ingestor",
    "ti_enrichment_worker", "detection_campaign_engine", "drift_scoring_engine",
]
RUNTIME_DEPS = ["psycopg[binary]>=3.2", "redis>=5.0"]
SKIP = {"__pycache__", "tests"}


def install_deps(target: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed argument list
        [sys.executable, "-m", "pip", "install", "--quiet", "--target", str(target),
         "--platform", "manylinux2014_x86_64", "--implementation", "cp", "--python-version", "3.12",
         "--only-binary=:all:", "--upgrade", *RUNTIME_DEPS],
        check=True,
    )


def _add_tree(zf: zipfile.ZipFile, source: Path, arc_root: str) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file() and not SKIP & set(path.relative_to(source).parts) and path.suffix != ".pyc":
            zf.write(path, f"{arc_root}/{path.relative_to(source).as_posix()}")


def build(functions: list[str], out: Path, skip_deps: bool = False) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    deps = out / ".deps"
    if not skip_deps:
        shutil.rmtree(deps, ignore_errors=True)
        install_deps(deps)
    built = []
    for name in functions:
        if name not in FUNCTIONS:
            raise SystemExit(f"unknown function {name!r}; expected one of {FUNCTIONS}")
        archive = out / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            _add_tree(zf, ROOT / name, name)
            _add_tree(zf, ROOT / "common", "common")
            if not skip_deps:
                for item in sorted(deps.iterdir()):
                    if item.is_dir():
                        _add_tree(zf, item, item.name)
                    elif item.suffix != ".pyc":
                        zf.write(item, item.name)
        built.append(archive)
    shutil.copyfile(ASL, out / ASL.name)
    return built


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("functions", nargs="*", default=FUNCTIONS)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument("--skip-deps", action="store_true")
    args = parser.parse_args()
    for archive in build(args.functions, args.out, args.skip_deps):
        print(f"{archive.name:36} {archive.stat().st_size / 1_048_576:6.2f} MiB")  # noqa: T201
    print(f"Upload: aws s3 sync {args.out} s3://<ArtifactBucket>/<ArtifactPrefix> --exclude '.deps/*'")  # noqa: T201


if __name__ == "__main__":
    main()
