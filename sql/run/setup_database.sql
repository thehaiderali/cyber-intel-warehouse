/*
   setup_database.sql
   Builds (or rebuilds) every database object and the seed data.
   WARNING: drops and recreates the staging and warehouse tables.

   Run after sql/00_create_database.sql:
     psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/run/setup_database.sql
*/

\set ON_ERROR_STOP on
SET client_min_messages = warning;

\ir ../01_create_schemas.sql
\ir ../02_staging_ddl.sql
\ir ../03_dw_ddl.sql
\ir ../04_functions.sql
\ir ../05_reporting_views.sql
\ir ../etl/10_seed_reference_data.sql

\echo 'Database objects and seed data created.'
