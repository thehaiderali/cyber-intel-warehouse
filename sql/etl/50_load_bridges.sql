/*
   50_load_bridges.sql
   bridge_cve_cwe              stg_cve_cwe  + dim_cve + dim_cwe
   bridge_cve_product          stg_cve_cpe  + dim_cve + dim_product
   bridge_product_software_map ref_software_product_map + dim_product + dim_software

   The CVE bridges hang off the current version of each CVE in the batch. NVD
   sends the complete weakness / configuration list with every CVE record, so
   the rows of the current version are replaced. A CVE that got a new version
   (SCD2) gets fresh rows; the old version keeps its rows as history.
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.batch_cve;
CREATE TEMP TABLE batch_cve AS
SELECT d.cve_key, d.cve_id
FROM dim_cve d
JOIN stg_cve s ON s.cve_id = d.cve_id
WHERE d.is_current;
CREATE INDEX ON batch_cve (cve_id);
ANALYZE batch_cve;


-- bridge_cve_cwe

DELETE FROM bridge_cve_cwe b USING batch_cve c WHERE b.cve_key = c.cve_key;

INSERT INTO bridge_cve_cwe (cve_key, cwe_key)
SELECT DISTINCT c.cve_key, w.cwe_key
FROM stg_cve_cwe s
JOIN batch_cve c ON c.cve_id = s.cve_id
JOIN dim_cwe   w ON w.cwe_code = s.cwe_code;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'bridge', 'Load bridge_cve_cwe', 'bridge_cve_cwe',
       (SELECT count(*) FROM stg_cve_cwe),
       (SELECT count(*) FROM bridge_cve_cwe b JOIN batch_cve c ON c.cve_key = b.cve_key);


-- bridge_cve_product

DELETE FROM bridge_cve_product b USING batch_cve c WHERE b.cve_key = c.cve_key;

INSERT INTO bridge_cve_product (cve_key, product_key, cpe_criteria, cpe_version, version_start_including,
                                version_start_excluding, version_end_including, version_end_excluding)
SELECT c.cve_key, p.product_key, s.cpe_criteria, s.cpe_version, s.version_start_including,
       s.version_start_excluding, s.version_end_including, s.version_end_excluding
FROM stg_cve_cpe s
JOIN batch_cve   c ON c.cve_id = s.cve_id
JOIN dim_product p ON p.vendor_name = s.cpe_vendor AND p.product_name = s.cpe_product
ON CONFLICT DO NOTHING;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'bridge', 'Load bridge_cve_product', 'bridge_cve_product',
       (SELECT count(*) FROM stg_cve_cpe),
       (SELECT count(*) FROM bridge_cve_product b JOIN batch_cve c ON c.cve_key = b.cve_key);


-- bridge_product_software_map (new products or software can appear in any batch)

WITH ins AS (
    INSERT INTO bridge_product_software_map (product_key, software_key, match_method, match_confidence, mapping_notes)
    SELECT p.product_key, s.software_key, m.match_method, m.match_confidence, m.mapping_notes
    FROM ref_software_product_map m
    JOIN dim_product  p ON p.vendor_name = m.cpe_vendor AND p.product_name = m.cpe_product
    JOIN dim_software s ON s.normalized_software_name = lower(m.software_name)
    ON CONFLICT (product_key, software_key) DO NOTHING
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'bridge', 'Load bridge_product_software_map', 'bridge_product_software_map',
       (SELECT count(*) FROM ref_software_product_map), (SELECT count(*) FROM ins),
       'rows_out = new mappings; total ' || ((SELECT count(*) FROM bridge_product_software_map) + (SELECT count(*) FROM ins));

DROP TABLE batch_cve;
