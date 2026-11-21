# Cyber Intel Warehouse

DL3004 Phase 2 - PostgreSQL implementation of the Cybersecurity Vulnerability Prioritization and Asset Risk Intelligence Data Warehouse designed in Phase 1.

**Team:** Afras Shahnawaz (24L-2547), Rana Nauman Iqbal (24L-2565), Haider Ali (24L-2522)

## Architecture

```
Source files (NVD JSON, EPSS CSV, CISA KEV JSON, asset inventory CSV)
        |
project_staging    raw_* (as-is)  ->  stg_* (cleaned, typed, de-duplicated)
        |
project_dw         dimensions, bridges, facts (surrogate keys)
        |
project_reporting  views for the business questions
```

## Database scripts

| Script | Purpose |
|---|---|
| `sql/00_create_database.sql` | Creates the `intel_dw` database |
| `sql/01_create_schemas.sql` | Creates `project_staging`, `project_dw`, `project_reporting` |
| `sql/02_staging_ddl.sql` | ETL audit log, raw landing tables, reference tables, cleaned staging tables |
| `sql/03_dw_ddl.sql` | 9 dimensions, 3 bridge tables, 3 fact tables |

Run order (PostgreSQL 15+):

```
psql -U postgres -d postgres -f sql/00_create_database.sql
psql -U postgres -d intel_dw -f sql/01_create_schemas.sql
psql -U postgres -d intel_dw -f sql/02_staging_ddl.sql
psql -U postgres -d intel_dw -f sql/03_dw_ddl.sql
```
