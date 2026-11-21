/*
   load_all_batches.sql
   Loads the full load and then every incremental batch in date order, then runs
   the warehouse-wide data quality checks. Batches already loaded are skipped,
   so this can be re-run at any time (e.g. after a new daily batch is added
   to the list below).

   Run from the repository root:
     psql -U postgres -d intel_dw -v data_dir=<path to cyber-threat-intel/data/sample_raw> -f sql/run/load_all_batches.sql
*/

\set ON_ERROR_STOP on

\set batch_id full_load
\ir load_batch.sql
\set batch_id 2026-10-09_185004
\ir load_batch.sql
\set batch_id 2026-10-10_045631
\ir load_batch.sql
\set batch_id 2026-10-11_044402
\ir load_batch.sql
\set batch_id 2026-10-12_045934
\ir load_batch.sql
\set batch_id 2026-10-13_060009
\ir load_batch.sql
\set batch_id 2026-10-15_034533
\ir load_batch.sql
\set batch_id 2026-10-16_034138
\ir load_batch.sql
\set batch_id 2026-10-17_033114
\ir load_batch.sql
\set batch_id 2026-10-18_033807
\ir load_batch.sql
\set batch_id 2026-10-19_034817
\ir load_batch.sql
\set batch_id 2026-10-21_034900
\ir load_batch.sql
\set batch_id 2026-10-24_034740
\ir load_batch.sql
\set batch_id 2026-10-25_034634
\ir load_batch.sql
\set batch_id 2026-10-26_035011
\ir load_batch.sql
\set batch_id 2026-10-28_044140
\ir load_batch.sql
\set batch_id 2026-10-29_045417
\ir load_batch.sql
\set batch_id 2026-10-30_045424
\ir load_batch.sql
\set batch_id 2026-10-31_044005
\ir load_batch.sql
\set batch_id 2026-11-01_045947
\ir load_batch.sql
\set batch_id 2026-11-02_050003
\ir load_batch.sql
\set batch_id 2026-11-03_054924
\ir load_batch.sql
\set batch_id 2026-11-04_052427
\ir load_batch.sql
\set batch_id 2026-11-05_054308
\ir load_batch.sql
\set batch_id 2026-11-06_054038
\ir load_batch.sql
\set batch_id 2026-11-07_051036
\ir load_batch.sql
\set batch_id 2026-11-08_050451
\ir load_batch.sql
\set batch_id 2026-11-09_051633
\ir load_batch.sql
\set batch_id 2026-11-10_063025
\ir load_batch.sql
\set batch_id 2026-11-11_051618
\ir load_batch.sql
\set batch_id 2026-11-12_062048
\ir load_batch.sql
\set batch_id 2026-11-13_054128
\ir load_batch.sql
\set batch_id 2026-11-14_053048
\ir load_batch.sql
\set batch_id 2026-11-16_052756
\ir load_batch.sql
\set batch_id 2026-11-17_070528
\ir load_batch.sql
\set batch_id 2026-11-18_062949
\ir load_batch.sql
\set batch_id 2026-11-19_063203
\ir load_batch.sql
\set batch_id 2026-11-20_061928
\ir load_batch.sql
\set batch_id 2026-11-21_060914
\ir load_batch.sql

\ir ../dq/71_dq_warehouse_checks.sql
