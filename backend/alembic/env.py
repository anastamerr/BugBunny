from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path
import socket
from urllib.parse import urlparse

from alembic import context
from sqlalchemy import engine_from_config, pool

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from src.config import get_settings
from src.models import Base  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    settings = get_settings()
    url = settings.alembic_database_url or settings.database_url
    env_file = BACKEND_ROOT / ".env"

    # If `backend/.env` isn't set up, the default URL points at a docker host `db` which
    # does not exist in this repo's docker-compose (Supabase is expected instead).
    if (
        "@db:" in url
        and settings.alembic_database_url is None
        and not os.environ.get("DATABASE_URL")
        and not env_file.exists()
    ):
        raise RuntimeError(
            "DATABASE_URL is not set. Create `backend/.env` from `backend/.env.example` "
            "and set DATABASE_URL to your Postgres (Supabase) connection string."
        )

    # Fast fail with a clear message when the configured host can't resolve.
    # This is a common pitfall with some Supabase direct hosts (`db.<ref>.supabase.co`)
    # that resolve IPv6-only in certain networks/regions.
    if not context.is_offline_mode():
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 5432
        if host:
            try:
                socket.getaddrinfo(host, port)
            except socket.gaierror as exc:
                if host.startswith("db.") and host.endswith(".supabase.co"):
                    raise RuntimeError(
                        f"Cannot resolve database host '{host}'. This often happens when the "
                        "Supabase direct hostname is IPv6-only but your environment is IPv4-only. "
                        "Use the Supabase 'Connection pooling' DATABASE_URL (pooler.supabase.com) "
                        "or set `ALEMBIC_DATABASE_URL` to the Session Pooler connection string, "
                        "or enable IPv6, then re-run `alembic upgrade head`."
                    ) from exc
                raise RuntimeError(
                    f"Cannot resolve database host '{host}'. Check DATABASE_URL/ALEMBIC_DATABASE_URL in `backend/.env`."
                ) from exc

    return url


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

