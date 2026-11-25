"""Alembic environment.

Only tables prefixed ``sc_`` are managed here. Legacy single-tenant tables
in the same SQLite file are ignored by autogenerate and never altered.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.v1 import models  # noqa: F401 - registers tables on Base.metadata
from app.v1.db import Base
from app.v1.settings import platform_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
VERSION_TABLE = "sc_alembic_version"


def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table":
        return bool(name) and name.startswith("sc_")
    table = getattr(obj, "table", None)
    if table is not None:
        return table.name.startswith("sc_")
    return True


def _url() -> str:
    return config.attributes.get("database_url") or platform_settings.database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        include_object=include_object,
        version_table=VERSION_TABLE,
        render_as_batch=_url().startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        _run(conn)


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_object=include_object,
        version_table=VERSION_TABLE,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
