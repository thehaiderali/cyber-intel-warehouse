# Phase 2 Rubric Checklist

Maps each Phase 2 requirement (DL3004 - Physical Data Warehouse, 40 marks) to the files in this repository.

## Marking scheme

| Rubric item | Marks | Where it is covered |
|---|---|---|
| Database Implementation | 10 | `sql/00_create_database.sql`, `sql/01_create_schemas.sql`, `sql/02_staging_ddl.sql`, `sql/03_dw_ddl.sql`, `sql/tests/test_01_ddl.sql` |
| ETL Pipeline | 15 | `sql/04_functions.sql`, `sql/etl/` (10 to 62), `sql/run/`, `sql/tests/test_02_etl.sql` |
| Surrogate Key Implementation | 5 | `sql/03_dw_ddl.sql`, `sql/etl/40-43_load_dim_*`, `sql/etl/60-62_load_fact_*` |
| Data Quality Validation | 10 | `sql/dq/70_dq_batch_checks.sql`, `sql/dq/71_dq_warehouse_checks.sql`, `reports/Data_Quality_Report.pdf` |

## Requirement by requirement

### 1. Data source creation
- Option A (public data): NVD CVE JSON, EPSS CSV, CISA KEV JSON, Cortexa asset inventory CSV (extract: `sql/etl/20_extract_batch.sql`).
- Option B (synthetic): 130 synthetic assets with injected dirty values (`sql/etl/21_generate_synthetic_assets.sql`).
- Minimum size: dimension records 100+, fact records 10,000+. See the status table at the bottom.

### 2. Warehouse architecture
Source files -> `project_staging` -> `project_dw` -> `project_reporting`
- Schemas created in `sql/01_create_schemas.sql`.
- Reporting views for business questions Q1 to Q12 and KPIs in `sql/05_reporting_views.sql`.

### 3. Staging layer
- Raw landing tables, cleaned `stg_*` tables and ETL audit tables: `sql/02_staging_ddl.sql`.
- Cleaning scripts: `sql/etl/30_clean_assets.sql`, `31_clean_nvd.sql`, `32_clean_epss.sql`, `33_clean_kev.sql`.
- Transformations: remove duplicates, handle NULLs, standardise text (for example " lahore " and "LAHORE" become Lahore), convert data types, reject invalid rows to `stg_reject`.
- Evidence: `reports/Data_Cleaning_Report.pdf`.

### 4. Dimensions and surrogate keys
- 9 dimensions, 3 bridges: `sql/03_dw_ddl.sql`.
- Loads: `sql/etl/40_load_dim_reference.sql`, `41_load_dim_product_software.sql`, `42_load_dim_asset.sql`, `43_load_dim_cve.sql`, `50_load_bridges.sql`.
- Every dimension has an identity surrogate key and keeps its business key (for example `asset_id` AST-APACHE-01 -> `asset_key` 1001).
- Key -1 is the reserved Unknown member in every dimension.
- `dim_asset` and `dim_cve` are SCD Type 2.

### 5. Fact loading
- `sql/etl/60_load_fact_vulnerability_snapshot.sql`, `61_load_fact_inventory_snapshot.sql`, `62_load_fact_exposure.sql`.
- Facts are loaded through business key -> surrogate key lookups.

### 6. Data quality validation
- Completeness, accuracy, integrity, uniqueness and validity checks: `sql/dq/70_dq_batch_checks.sql` (per batch) and `71_dq_warehouse_checks.sql` (whole warehouse).
- Integrity target: fact rows without a matching dimension row = 0.
- Results are stored in `project_staging.dq_check_result` and shown in `reports/Data_Quality_Report.pdf`.

## Deliverables

| Deliverable | File |
|---|---|
| PostgreSQL database SQL scripts | `sql/00_create_database.sql`, `sql/01_create_schemas.sql` |
| Staging schema SQL | `sql/02_staging_ddl.sql` |
| DW schema SQL | `sql/03_dw_ddl.sql` |
| ETL scripts | `sql/etl/`, `sql/run/` |
| Data Cleaning Report (PDF) | `reports/Data_Cleaning_Report.pdf` |
| Dimension load scripts | `sql/etl/40-43_load_dim_*`, `50_load_bridges.sql` |
| Fact load scripts | `sql/etl/60-62_load_fact_*` |
| Data Quality Report (PDF) | `reports/Data_Quality_Report.pdf` |
| GitHub repository link | https://github.com/thehaiderali/cyber-intel-warehouse |

## Volume status

Full load of all 39 batches (`sql/run/load_all_batches.sql`):

| Table | Rows |
|---|---|
| fact_vulnerability_intelligence_snapshot | 7,590 |
| fact_asset_software_inventory_snapshot | 5,499 |
| fact_asset_vulnerability_exposure | 33,791 |
| **Total fact rows (target 10,000+)** | **46,880** |

`fact_asset_vulnerability_exposure` alone is above the 10,000 target. The per-table volume check on `fact_vulnerability_intelligence_snapshot` (7,590 rows) stays a WARN in the Data Quality Report because it is below 10,000 on its own.

Dimension records (target 100+): see section 2 of `reports/Data_Quality_Report.pdf` (`dim_cve`, `dim_asset`, `dim_product` and others are all above 100).
