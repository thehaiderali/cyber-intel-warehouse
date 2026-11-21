/*
   20_extract_batch.sql
   Extract: copy one batch of source files into the raw_* landing tables as-is.

   Called by sql/run/load_batch.sql with these psql variables:
     batch_id    'full_load' or the incremental folder name, e.g. '2026-10-10_045631'
     nvd_file    path of the NVD JSON file
     epss_file   path of the EPSS CSV file
     kev_file    path of the KEV JSON file
     asset_file  path of the asset inventory CSV (optional - only the full load has one)

   JSON and the commented EPSS CSV are read with \copy one physical line per
   row into raw_file_line (FORMAT csv with delimiter/quote characters that never
   occur in the files, so every line arrives untouched). The JSON lines are then
   joined back into one JSONB document and the EPSS lines are split into fields.

   psql does not expand variables inside \copy, so each \copy command is built
   in the variable copy_cmd and then executed with :copy_cmd.
*/

\encoding UTF8
SET search_path = project_staging;

\set line_copy_options ' WITH (FORMAT csv, DELIMITER E''\\x01'', QUOTE E''\\x02'')'

TRUNCATE raw_nvd_document, raw_kev_document, raw_epss, raw_asset RESTART IDENTITY;


-- 1. NVD CVE feed (JSON)

TRUNCATE raw_file_line RESTART IDENTITY;
\set copy_cmd '\\copy project_staging.raw_file_line (line) FROM ' :'nvd_file' :line_copy_options
:copy_cmd

INSERT INTO raw_nvd_document (batch_id, source_file, document)
SELECT :'batch_id', :'nvd_file', string_agg(line, E'\n' ORDER BY line_no)::JSONB
FROM raw_file_line;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'extract', 'Extract NVD JSON', 'raw_nvd_document',
       (SELECT count(*) FROM raw_file_line),
       jsonb_array_length(document -> 'vulnerabilities'),
       'rows_in = file lines, rows_out = CVE records in the document (totalResults '
           || coalesce(document ->> 'totalResults', '?') || ')'
FROM raw_nvd_document;


-- 2. EPSS scores (CSV with a comment line before the header)

TRUNCATE raw_file_line RESTART IDENTITY;
\set copy_cmd '\\copy project_staging.raw_file_line (line) FROM ' :'epss_file' :line_copy_options
:copy_cmd

INSERT INTO raw_epss (batch_id, source_file, source_line_no, cve, epss, percentile, model_version, score_date_raw)
SELECT :'batch_id', :'epss_file', l.line_no,
       split_part(l.line, ',', 1),
       split_part(l.line, ',', 2),
       split_part(l.line, ',', 3),
       substring(c.line FROM 'model_version:([^,]+)'),
       substring(c.line FROM 'score_date:([^,]+)')
FROM raw_file_line l
CROSS JOIN LATERAL (SELECT line FROM raw_file_line WHERE line LIKE '#%' ORDER BY line_no LIMIT 1) c
WHERE l.line NOT LIKE '#%'
  AND lower(l.line) NOT LIKE 'cve,%'          -- header row
  AND l.line IS NOT NULL;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'extract', 'Extract EPSS CSV', 'raw_epss',
       (SELECT count(*) FROM raw_file_line),
       (SELECT count(*) FROM raw_epss),
       'rows_in = file lines (incl. comment + header), rows_out = data rows';


-- 3. CISA KEV catalog (JSON)

TRUNCATE raw_file_line RESTART IDENTITY;
\set copy_cmd '\\copy project_staging.raw_file_line (line) FROM ' :'kev_file' :line_copy_options
:copy_cmd

INSERT INTO raw_kev_document (batch_id, source_file, document)
SELECT :'batch_id', :'kev_file', string_agg(line, E'\n' ORDER BY line_no)::JSONB
FROM raw_file_line;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'extract', 'Extract KEV JSON', 'raw_kev_document',
       (SELECT count(*) FROM raw_file_line),
       jsonb_array_length(document -> 'vulnerabilities'),
       'rows_in = file lines, rows_out = KEV entries (catalogVersion '
           || coalesce(document ->> 'catalogVersion', '?') || ')'
FROM raw_kev_document;

TRUNCATE raw_file_line RESTART IDENTITY;


-- 4. Asset inventory (CSV) - only when the batch has one

\if :{?asset_file}
\set copy_cmd '\\copy project_staging.raw_asset (asset_id, hostname, ip_address, os_name, os_version, software_name, software_version, department, owner, criticality, exposure, environment, location, status) FROM ' :'asset_file' ' WITH (FORMAT csv, HEADER true)'
:copy_cmd

UPDATE raw_asset SET batch_id = :'batch_id', source_file = :'asset_file' WHERE batch_id IS NULL;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'extract', 'Extract asset inventory CSV', 'raw_asset', count(*), count(*), :'asset_file'
FROM raw_asset;
\else
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, status, message)
VALUES (:'batch_id', 'extract', 'Extract asset inventory CSV', 'raw_asset', 0, 0, 'Skipped',
        'No asset file in this batch - current inventory is carried forward');
\endif
