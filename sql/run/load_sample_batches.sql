/*
   load_sample_batches.sql
   Quick test load: the full load plus the first two incremental batches,
   then the warehouse-wide data quality checks. Takes about two minutes.
   Use load_all_batches.sql for the complete history.

   Run from the repository root:
     psql -U postgres -d intel_dw -v data_dir=<path to cyber-threat-intel/data/sample_raw> -f sql/run/load_sample_batches.sql
*/

\set ON_ERROR_STOP on

\set batch_id full_load
\ir load_batch.sql
\set batch_id 2026-10-09_185004
\ir load_batch.sql
\set batch_id 2026-10-10_045631
\ir load_batch.sql

\ir ../dq/71_dq_warehouse_checks.sql
