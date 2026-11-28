# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Creates or drops the PostgreSQL database of one reference-estate e2e run (support/estate.ts).

usage: estate_db.py create ADMIN_DSN DBNAME SCHEMA_SQL   prints the DSN of the new database on one line
       estate_db.py drop ADMIN_DSN DBNAME

ADMIN_DSN names an existing PostgreSQL 16 server and a role that may create databases (E2E_ESTATE_DATABASE_URL). The run's
database is its own, so concurrent runs and the reference applications never share a table. Nothing here prints a password.
"""
import re
import sys
from urllib.parse import urlsplit, urlunsplit

import psycopg


def with_database(dsn, name):
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, "/" + name, "", ""))


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ("create", "drop"):
        raise SystemExit("usage")
    action, admin, name = sys.argv[1], sys.argv[2], sys.argv[3]
    if not re.fullmatch(r"estate_[0-9a-f]{12}", name):
        raise SystemExit("invalid database name")
    with psycopg.connect(admin, autocommit=True) as connection:
        if action == "drop":
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            return
        connection.execute(f'CREATE DATABASE "{name}"')
    dsn = with_database(admin, name)
    with open(sys.argv[4], encoding="utf-8") as schema, psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(schema.read())
    print(dsn)


main()
