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
    if "alerts" not in inspector.get_table_names():
        return  # create_all() will make it fresh with every column

    existing_columns = {col["name"] for col in inspector.get_columns("alerts")}
    new_columns = {
        "ip_reputation": "VARCHAR",
        "hash_reputation": "VARCHAR",
        "threat_score": "INTEGER",
        "mitre_technique": "VARCHAR",
        "risk_score": "INTEGER",
        "response_action": "VARCHAR",
        "response_playbook": "VARCHAR",
        "response_status": "VARCHAR",
    }

    with engine.begin() as conn:
        for column_name, column_type in new_columns.items():
            if column_name not in existing_columns:
                conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}"))