/*
   43_load_dim_cve.sql
   stg_cve -> dim_cve (SCD Type 2)

   Business key  cve_id  ->  surrogate key cve_key

   Tracked (Type 2) attributes, hashed into row_hash:
     source_identifier, vulnerability_status, description_en, primary_cwe_code
   A change in any of them closes the current row and opens a new version.

   Overwritten (Type 1) attributes on the current row:
     last_modified_at, last_modified_date_key, published_date_key
   NVD re-publishes a CVE whenever anything (references, configurations, scores)
   changes, so lastModified alone does not create a new version.
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.cve_src;
CREATE TEMP TABLE cve_src AS
SELECT s.cve_id, s.source_identifier, s.vulnerability_status, s.description_en, s.primary_cwe_code,
       s.last_modified_at,
       fn_date_key(s.published_at::DATE)     AS published_date_key,
       fn_date_key(s.last_modified_at::DATE) AS last_modified_date_key,
       md5(concat_ws('|', s.source_identifier, s.vulnerability_status, s.description_en, s.primary_cwe_code)) AS row_hash
FROM stg_cve s;
CREATE INDEX ON cve_src (cve_id);
ANALYZE cve_src;

-- Type 1 refresh of the current row when only lastModified / dates changed
UPDATE dim_cve d
SET last_modified_at       = s.last_modified_at,
    last_modified_date_key = s.last_modified_date_key,
    published_date_key     = s.published_date_key
FROM cve_src s
WHERE d.cve_id = s.cve_id AND d.is_current AND d.row_hash = s.row_hash
  AND d.last_modified_at IS DISTINCT FROM s.last_modified_at;

-- tracked attributes changed again on the same day: overwrite today's version
UPDATE dim_cve d
SET source_identifier = s.source_identifier, vulnerability_status = s.vulnerability_status,
    description_en = s.description_en, primary_cwe_code = s.primary_cwe_code,
    last_modified_at = s.last_modified_at, last_modified_date_key = s.last_modified_date_key,
    published_date_key = s.published_date_key, row_hash = s.row_hash
FROM cve_src s
WHERE d.cve_id = s.cve_id AND d.is_current AND d.row_hash <> s.row_hash
  AND d.effective_start_date = :'batch_date'::DATE;

-- tracked attributes changed: close the current version
DROP TABLE IF EXISTS pg_temp.cve_changed;
CREATE TEMP TABLE cve_changed AS
SELECT d.cve_key, d.cve_id
FROM dim_cve d
JOIN cve_src s ON s.cve_id = d.cve_id
WHERE d.is_current AND d.row_hash <> s.row_hash
  AND d.effective_start_date < :'batch_date'::DATE;

UPDATE dim_cve d
SET is_current = FALSE, effective_end_date = :'batch_date'::DATE - 1
FROM cve_changed c
WHERE d.cve_key = c.cve_key;

-- new CVEs and new versions
INSERT INTO dim_cve (cve_id, source_identifier, vulnerability_status, description_en, primary_cwe_code,
                     published_date_key, last_modified_date_key, last_modified_at, record_source, row_hash,
                     effective_start_date)
SELECT s.cve_id, s.source_identifier, s.vulnerability_status, s.description_en, s.primary_cwe_code,
       s.published_date_key, s.last_modified_date_key, s.last_modified_at, 'NVD', s.row_hash,
       :'batch_date'::DATE
FROM cve_src s
WHERE NOT EXISTS (SELECT 1 FROM dim_cve d WHERE d.cve_id = s.cve_id AND d.is_current)
ORDER BY s.cve_id;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'dimension', 'Load dim_cve (SCD2)', 'dim_cve',
       (SELECT count(*) FROM cve_src),
       (SELECT count(*) FROM dim_cve WHERE effective_start_date = :'batch_date'::DATE AND cve_key > 0),
       format('new versions for changed CVEs %s; current CVEs %s; total rows %s',
              (SELECT count(*) FROM cve_changed),
              (SELECT count(*) FROM dim_cve WHERE is_current AND cve_key > 0),
              (SELECT count(*) FROM dim_cve WHERE cve_key > 0));

DROP TABLE cve_src, cve_changed;
