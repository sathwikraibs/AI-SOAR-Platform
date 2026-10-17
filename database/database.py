from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///database/soar.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def migrate_schema():
    """
    Adds any model columns missing from an already-existing sqlite table.

    Base.metadata.create_all() only creates tables that don't exist yet --
    it will NOT add new columns to a table a teammate already has locally
    (e.g. database/soar.db from before the Day 3 threat-intel/response
    columns were added). Without this, anyone with an existing soar.db
    would hit "no such column" errors after pulling this change. Safe to
    call every startup: it's a no-op once the columns exist.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    # table -> {column: sql type}. A table that doesn't exist yet is skipped:
    # create_all() will make it fresh with every column.
    wanted = {
        "alerts": {
            "ip_reputation": "VARCHAR",
            "hash_reputation": "VARCHAR",
            "threat_score": "INTEGER",
            "mitre_technique": "VARCHAR",
            "risk_score": "INTEGER",
            "response_action": "VARCHAR",
            "response_playbook": "VARCHAR",
            "response_status": "VARCHAR",
            "rule_key": "VARCHAR",
            "host": "VARCHAR",
        },
        "endpoint_agents": {
            "owner": "VARCHAR",
            "monitoring_enabled": "BOOLEAN NOT NULL DEFAULT 1",
            "usage_json": "VARCHAR",
        },
    }

    with engine.begin() as conn:
        for table, new_columns in wanted.items():
            if table not in existing_tables:
                continue
            existing_columns = {col["name"] for col in inspector.get_columns(table)}
            for column_name, column_type in new_columns.items():
                if column_name not in existing_columns:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_type}"))
