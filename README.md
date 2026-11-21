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
| `sql/tests/test_01_ddl.sql` | Automated structure and constraint tests |

Run order (PostgreSQL 15+):

```
psql -U postgres -d postgres -f sql/00_create_database.sql
psql -U postgres -d intel_dw -f sql/01_create_schemas.sql
psql -U postgres -d intel_dw -f sql/02_staging_ddl.sql
psql -U postgres -d intel_dw -f sql/03_dw_ddl.sql
```

## Tests

`sql/tests/test_01_ddl.sql` checks the structure against the Phase 1 ERD (every table and column, primary and foreign keys) and checks that the constraints accept valid rows and reject invalid ones (business rules BR-01 to BR-07, fact grain, SCD Type 2, surrogate keys). It runs in a rolled-back transaction, restores identity sequences, and exits non-zero if any test fails.

```
psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_01_ddl.sql
```

## Differences from the Phase 1 design

| Change | Reason |
|---|---|
| Fact flags (`version_match_flag`, `internet_exposed_flag`, ...) are `SMALLINT` 0/1 instead of `BOOLEAN` | Consistent with `kev_listed_flag` in the data dictionary; flags can be summed |
| `bridge_cve_product.cpe_version`, `cpe_criteria` added | NVD often pins an exact affected version instead of a range; needed for version matching |
| `fact_asset_vulnerability_exposure.first_detected_date_key` added | Source for `days_open` |
| `dim_risk_band.remediation_sla_days` added | Remediation due date for findings that are not in KEV |
| `dim_cve` / `dim_asset` carry `row_hash` (and `last_modified_at` on `dim_cve`) | Change detection for SCD Type 2 |
| Key `-1` reserved in every dimension | "Unknown" member so fact foreign keys are never NULL |
