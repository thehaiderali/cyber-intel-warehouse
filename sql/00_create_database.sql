/*
   00_create_database.sql
   Creates the warehouse database.

   Run while connected to the default "postgres" database:
       psql -U postgres -d postgres -f sql/00_create_database.sql

   CREATE DATABASE cannot run inside a transaction block or a DO block, so the
   "create if missing" check uses psql's \gexec.
*/

SELECT 'CREATE DATABASE intel_dw ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'intel_dw')
\gexec

COMMENT ON DATABASE intel_dw IS
    'DL3004 - Cybersecurity Vulnerability Prioritization and Asset Risk Intelligence Data Warehouse';
