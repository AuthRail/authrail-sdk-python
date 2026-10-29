"""Run the installed candidate with real server services in disposable PostgreSQL.

Requires sibling server source/dependencies, Docker and an already verified
native sidecar candidate. Existing services, environment files and data are not used.
"""

import argparse
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import uuid
import venv

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--wheel", type=pathlib.Path, required=True)
parser.add_argument("--sidecar", type=pathlib.Path, required=True)
options = parser.parse_args()
wheel = options.wheel.resolve(strict=True)
sidecar_binary = options.sidecar.resolve(strict=True)
root = pathlib.Path(__file__).resolve().parents[2]
server = root / "authrail-server"
if os.name != "posix":
    raise SystemExit("Run this maintainer verification on macOS or Linux.")
if not (server / "node_modules/tsx/dist/loader.mjs").is_file():
    raise SystemExit("Install the sibling authrail-server dependencies before verification.")
name = "authrail-python-connected-" + uuid.uuid4().hex[:10]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


env = dict(
    os.environ,
    DOTENV_CONFIG_PATH="/dev/null",
    DOTENV_CONFIG_QUIET="true",
    OTEL_SDK_ENABLED="false",
    AUTHRAIL_LOCAL_RUNTIME_VERIFICATION="1",
)
try:
    run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_USER=fixture",
            "-e",
            "POSTGRES_PASSWORD=isolated-python-only",
            "-e",
            "POSTGRES_DB=authrail_slice8_verify",
            "pgvector/pgvector:pg17",
        ],
        stdout=subprocess.DEVNULL,
    )
    for _ in range(100):
        if (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "fixture",
                    "-d",
                    "authrail_slice8_verify",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Disposable PostgreSQL unavailable")
    port = (
        subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True)
        .strip()
        .rsplit(":", 1)[1]
    )
    for hook in [
        "AUTHRAIL_VERIFY_AGENT_NODE",
        "AUTHRAIL_VERIFY_CONTEXT_NODE",
        "AUTHRAIL_VERIFY_NODE",
        "AUTHRAIL_VERIFY_GO",
    ]:
        env.pop(hook, None)
    env["DATABASE_URL"] = (
        f"postgres://fixture:isolated-python-only@127.0.0.1:{port}/authrail_slice8_verify"
    )
    with tempfile.TemporaryDirectory(prefix="authrail-python-connected-") as scratch:
        work = pathlib.Path(scratch)
        venv.EnvBuilder(with_pip=True).create(work / "venv")
        python = work / "venv/bin/python"
        run([str(python), "-m", "pip", "install", str(wheel)], stdout=subprocess.DEVNULL)
        migration = work / "migrate.ts"
        migration.write_text(
            "\n".join(
                [
                    "import { createRequire } from 'node:module';",
                    "const require=createRequire("
                    + json.dumps(str(server / "package.json"))
                    + ");",
                    "const {Pool}=require('pg');",
                    "import {migratePostgresDatabase} from "
                    + json.dumps(str(server / "src/infra/database/migrate-postgres-database.ts"))
                    + ";",
                    "const pool=new Pool({connectionString:process.env.DATABASE_URL});",
                    "async function main(){ const c=await pool.connect(); try {",
                    "await migratePostgresDatabase(c,{migrationsFolder:"
                    + json.dumps(str(server / "drizzle"))
                    + "});",
                    "} finally { c.release(); await pool.end(); }}",
                    "void main().catch(e=>{console.error(e);process.exitCode=1;});",
                ]
            )
        )
        loader = str(server / "node_modules/tsx/dist/loader.mjs")
        run(["node", "--import", loader, str(migration)], cwd=server, env=env)
        print(
            "Disposable PostgreSQL migrated; installed wheel isolated from checkout.",
            flush=True,
        )
        env.update(
            AUTHRAIL_VERIFY_SIDECAR=str(sidecar_binary),
            AUTHRAIL_VERIFY_PYTHON=str(
                root / "authrail-sdk-python/verification/connected_client.py"
            ),
            AUTHRAIL_VERIFY_PYTHON_EXECUTABLE=str(python),
        )
        # The process group belongs only to this fixture; timeout cleanup cannot
        # leave its sidecar listening after the disposable database is removed.
        process = subprocess.Popen(
            ["node", "--import", loader, "scripts/verify-runtime-sidecar-effects.ts"],
            cwd=server,
            env=env,
            start_new_session=True,
        )
        try:
            status = process.wait(timeout=120)
            if status:
                raise RuntimeError(f"Connected verification failed with exit code {status}")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

finally:
    subprocess.run(
        ["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
