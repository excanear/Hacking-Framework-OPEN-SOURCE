# Alembic database migrations

This directory contains Alembic migration scripts for the Security Research Platform.

## Setup

```bash
# Install Alembic (included in requirements.txt)
pip install alembic

# Initialise (already done — do NOT re-run)
# alembic init migrations

# Generate a new migration after model changes
alembic revision --autogenerate -m "describe_change"

# Apply all pending migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1
```

## Notes

- Always review auto-generated migrations before applying them.
- Never edit a migration that has already been applied to a production database.
- For development convenience `database.database.init_database()` creates tables
  directly from metadata, but Alembic should be used in production.
