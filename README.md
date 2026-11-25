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

## ETL pipeline (SQL only, run with psql)

```
sql/04_functions.sql            cleaning, version-range matching, date keys, risk scores
sql/05_reporting_views.sql      project_reporting views for business questions Q1-Q12 + KPIs
sql/etl/10_seed_reference_data  controlled values, software->CPE map, dim_date, risk bands, unknown members
sql/etl/20_extract_batch        raw files -> raw_* (psql \copy, as-is)
sql/etl/21_generate_synthetic   130 synthetic assets with injected dirty data (Option B)
sql/etl/30-33_clean_*           raw_* -> stg_* (dedup, NULLs, standardise text, types, rejects)
sql/etl/40-43_load_dim_*        dimensions with surrogate keys (SCD2 for dim_asset, dim_cve)
sql/etl/50_load_bridges         CVE-product, CVE-CWE, product-software bridges
sql/etl/60-62_load_fact_*       facts via business key -> surrogate key lookups
sql/dq/70_dq_batch_checks       per batch: row reconciliation, EPSS/CVSS/KEV reconciliation, formula checks
sql/dq/71_dq_warehouse_checks   integrity (orphan FKs = 0), uniqueness, validity, completeness
sql/run/                        setup_database, load_batch, load_sample_batches, load_all_batches
```

```
psql -U postgres -d postgres -f sql/00_create_database.sql
psql -U postgres -d intel_dw -f sql/run/setup_database.sql
psql -U postgres -d intel_dw -v data_dir=<cyber-threat-intel/data/sample_raw> -f sql/run/load_sample_batches.sql   # ~2 min
psql -U postgres -d intel_dw -v data_dir=<cyber-threat-intel/data/sample_raw> -f sql/run/load_all_batches.sql      # full history
psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_02_etl.sql
```

Each batch runs in one transaction and is skipped if already loaded (`etl_batch_log` watermark).
Cleaning results: `project_staging.etl_cleaning_stat`, `stg_reject`, `etl_step_log`. Data quality results: `project_staging.dq_check_result`.

Risk bands (Phase 1 did not define thresholds): Critical >= 70, High 50-69.99, Medium 30-49.99, Low < 30; fix targets 15/30/60/90 days.

Full load result (all 39 batches, `sql/run/load_all_batches.sql`): 141 assets (from 243 raw rows: 93 duplicates, 5 BR-06, 4 missing IDs), 72,009 `dim_cve` rows (all versions), 46,880 fact rows (33,791 exposure, 7,590 vulnerability snapshot, 5,499 inventory), 0 FAIL in the data quality checks. The 10,000+ fact-row target is met. A smaller sample load (full load + 2 batches) is available with `load_sample_batches.sql`.
