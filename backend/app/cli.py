"""Bootstrap CLI - for the steps that must happen before anyone can log in. Run as a one-off ECS task with the
backend image (infra/README.md), or locally against the dev database:

    python -m app.cli create-admin --email alice@example.com --name "Alice Admin" --sso-subject <IdP sub>
    python -m app.cli register-accounts --file accounts.csv

accounts.csv columns: account_id,name,environment,owner,regions[,discovery_role_arn,response_role_arn]
(regions separated by ";"). Already-registered accounts are skipped. Everything is audited as the CLI actor.
After the first admin exists, use the governance API instead.
"""

import argparse
import asyncio
import csv
import sys
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from app.database import SessionLocal
from app.services import registry_service as reg

CLI_ACTOR = reg.Actor(email="cli@sas-platform.internal", role="System")


async def create_admin(email: str, name: str, sso_subject: str) -> int:
    async with SessionLocal() as db:
        if await reg._active_admins(db):  # noqa: SLF001
            print("An active Security Admin already exists; add further admins through the governance API.")  # noqa: T201
            return 2
        user = await reg.create_user(db, reg.UserCreate(email=email, full_name=name, role="Security Admin",
                                                        sso_subject_id=sso_subject), CLI_ACTOR)
        print(f"Created Security Admin {user.email} ({user.id})")  # noqa: T201
    return 0


async def register_accounts(path: Path) -> int:
    created, skipped, failed = 0, 0, 0
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    async with SessionLocal() as db:
        for line, row in enumerate(rows, start=2):
            try:
                body = reg.AccountCreate(
                    account_id=row["account_id"].strip(), name=row["name"].strip(),
                    environment=row["environment"].strip(), owner=row["owner"].strip(),
                    regions=[r.strip() for r in row.get("regions", "us-east-1").split(";") if r.strip()],
                    discovery_role_arn=(row.get("discovery_role_arn") or "").strip() or None,
                    response_role_arn=(row.get("response_role_arn") or "").strip() or None,
                )
                await reg.create_account(db, body, CLI_ACTOR)
                created += 1
            except HTTPException as exc:
                if exc.status_code != 409:
                    raise
                skipped += 1
            except (ValidationError, KeyError) as exc:
                failed += 1
                print(f"line {line}: {exc}", file=sys.stderr)  # noqa: T201
    print(f"registered {created}, already present {skipped}, invalid {failed}")  # noqa: T201
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create the first Security Admin")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", required=True)
    admin.add_argument("--sso-subject", required=True, help="the IdP 'sub' claim for this person")
    accounts = sub.add_parser("register-accounts", help="register AWS accounts from a CSV file")
    accounts.add_argument("--file", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "create-admin":
        return asyncio.run(create_admin(args.email, args.name, args.sso_subject))
    return asyncio.run(register_accounts(args.file))


if __name__ == "__main__":
    sys.exit(main())
