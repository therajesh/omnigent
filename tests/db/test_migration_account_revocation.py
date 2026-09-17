"""Upgrade binds existing durable authority to an account generation."""

from pathlib import Path

import sqlalchemy as sa
from alembic import command

from omnigent.db.utils import _build_alembic_config, get_or_create_engine


def test_account_revocation_migration_preserves_identity_and_grants(tmp_path: Path) -> None:
    uri = f"sqlite:///{tmp_path / 'account-migration.db'}"
    engine = get_or_create_engine(uri)
    config = _build_alembic_config(uri)
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "gh1b2c3d4e5f")
        connection.execute(
            sa.text(
                "INSERT INTO users (id, is_admin, password_hash) VALUES ('alice', 1, "
                "'existing-hash'), ('external', 0, NULL)"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO device_grants (id, device_code_hash, user_code, status, "
                "user_id, created_at, expires_at, refresh_token_hash) VALUES ('grant', "
                "'device', 'code', 4, 'alice', 1, 2, 'refresh')"
            )
        )
        command.upgrade(config, "head")
        account = connection.execute(
            sa.text(
                "SELECT account_generation, password_hash, is_admin, deleted_at FROM "
                "users WHERE id = 'alice'"
            )
        ).one()
        assert len(account.account_generation) == 32
        assert (account.password_hash, account.is_admin, account.deleted_at) == (
            "existing-hash",
            1,
            None,
        )
        grant = connection.execute(
            sa.text(
                "SELECT account_generation, refresh_token_hash FROM device_grants WHERE "
                "id = 'grant'"
            )
        ).one()
        assert grant == (account.account_generation, "refresh")
        assert (
            connection.execute(
                sa.text("SELECT account_generation FROM users WHERE id = 'external'")
            ).scalar_one()
            is None
        )
        connection.execute(
            sa.text(
                "UPDATE users SET deleted_at = 1, password_hash = NULL, is_admin = 0 "
                "WHERE id = 'alice'"
            )
        )
        command.downgrade(config, "gh1b2c3d4e5f")
        assert (
            connection.execute(
                sa.text("SELECT COUNT(*) FROM users WHERE id = 'alice'")
            ).scalar_one()
            == 0
        )
