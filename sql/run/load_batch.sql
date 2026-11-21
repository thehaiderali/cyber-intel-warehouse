/*
   load_batch.sql
   Runs the whole ETL for ONE source batch:
     extract -> clean (staging) -> dimensions -> bridges -> facts -> batch DQ checks

   psql variables
     data_dir   folder that contains full_load/ and incremental/  (required)
     batch_id   'full_load' or an incremental folder name, e.g. 2026-10-10_045631  (required)

   The batch runs in one transaction: if any step fails nothing of the batch is
   kept and it can simply be run again. A batch already logged as Success in
   etl_batch_log is skipped (watermark), so re-running is safe.

   Example
     psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -v data_dir=C:/data/sample_raw -v batch_id=full_load -f sql/run/load_batch.sql
*/

\set ON_ERROR_STOP on
SET client_min_messages = warning;

SELECT :'batch_id' = 'full_load' AS is_full_load,
       EXISTS (SELECT 1 FROM project_staging.etl_batch_log
               WHERE batch_id = :'batch_id' AND status = 'Success') AS already_loaded
\gset

\if :already_loaded
\echo 'Batch' :batch_id 'was already loaded - skipped'
\else

-- file names: full load files have fixed names, incremental files carry the batch id
\if :is_full_load
\set load_type full
\set batch_date 2026-10-08
\set nvd_file   :data_dir/full_load/nvd_cves_full_sample_prev.json
\set epss_file  :data_dir/full_load/epss_full_sample.csv
\set kev_file   :data_dir/full_load/kev_full_sample.json
\set asset_file :data_dir/full_load/cortexa_assets_full_sample.csv
\else
\set load_type incremental
SELECT left(:'batch_id', 10) AS batch_date \gset
\set nvd_file   :data_dir/incremental/:batch_id/nvd_:batch_id.json
\set epss_file  :data_dir/incremental/:batch_id/epss_:batch_id.csv
\set kev_file   :data_dir/incremental/:batch_id/kev_:batch_id.json
\unset asset_file
\endif

\echo '==>' :batch_id '(' :load_type ', batch date' :batch_date ')'
\timing on

BEGIN;

INSERT INTO project_staging.etl_batch_log (batch_id, batch_date, load_type)
VALUES (:'batch_id', :'batch_date', :'load_type')
ON CONFLICT (batch_id) DO UPDATE
    SET status = 'Running', started_at = clock_timestamp(), finished_at = NULL;

\ir ../etl/20_extract_batch.sql
\if :is_full_load
\ir ../etl/21_generate_synthetic_assets.sql
\endif
\ir ../etl/30_clean_assets.sql
\ir ../etl/31_clean_nvd.sql
\ir ../etl/32_clean_epss.sql
\ir ../etl/33_clean_kev.sql
\ir ../etl/40_load_dim_reference.sql
\ir ../etl/41_load_dim_product_software.sql
\ir ../etl/42_load_dim_asset.sql
\ir ../etl/43_load_dim_cve.sql
\ir ../etl/50_load_bridges.sql
\ir ../etl/60_load_fact_vulnerability_snapshot.sql
\ir ../etl/61_load_fact_inventory_snapshot.sql
\ir ../etl/62_load_fact_exposure.sql
\ir ../dq/70_dq_batch_checks.sql

UPDATE project_staging.etl_batch_log
SET status = 'Success', finished_at = clock_timestamp()
WHERE batch_id = :'batch_id';

COMMIT;

\timing off
\endif
