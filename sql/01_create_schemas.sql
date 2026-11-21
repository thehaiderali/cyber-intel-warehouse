/*
   01_create_schemas.sql
   Creates the three warehouse layers.

       Source files  ->  project_staging  ->  project_dw  ->  project_reporting

   project_staging   : raw landing tables (loaded as-is) + cleaned stg_* tables,
                       reference/mapping seeds and the ETL audit log.
   project_dw        : the dimensional model (dimensions, bridges, facts)
                       with surrogate keys.
   project_reporting : read-only views that answer the business questions.

   Run: psql -U postgres -d intel_dw -f sql/01_create_schemas.sql
*/

SET client_min_messages = warning;

CREATE SCHEMA IF NOT EXISTS project_staging;
CREATE SCHEMA IF NOT EXISTS project_dw;
CREATE SCHEMA IF NOT EXISTS project_reporting;

COMMENT ON SCHEMA project_staging   IS 'Landing + cleansing layer: raw_* tables hold source data as-is, stg_* tables hold cleaned and typed data.';
COMMENT ON SCHEMA project_dw        IS 'Dimensional warehouse layer: dimensions, bridge tables and fact tables keyed by surrogate keys.';
COMMENT ON SCHEMA project_reporting IS 'Presentation layer: views built on project_dw for SQL reporting and Power BI.';
