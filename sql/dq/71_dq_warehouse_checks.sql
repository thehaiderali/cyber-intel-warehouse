/*
   71_dq_warehouse_checks.sql
   Warehouse-wide data quality checks, run after the batches are loaded.
   Results go to project_staging.dq_check_result with batch_id NULL
   (the previous warehouse-wide results are replaced).

   Integrity     fact and bridge rows without a matching dimension row = 0;
                 use of the "Unknown" (-1) members is reported
   Uniqueness    one current SCD2 row per natural key, no overlapping SCD2 date
                 ranges, unique natural keys, no duplicate rows at fact grain
   Validity      score ranges, risk band consistent with the score, KEV dates,
                 controlled values
   Completeness  every loaded batch has snapshot rows; KEV CVEs missing from
                 NVD; Phase 2 volume targets (100+ dimension rows, 10,000+ fact rows)
   Accuracy      exposure measures equal the vulnerability snapshot of the same
                 CVE and date

   Run: psql -U postgres -d intel_dw -f sql/dq/71_dq_warehouse_checks.sql
*/

\set ON_ERROR_STOP on
SET client_min_messages = warning;
SET search_path = project_dw, project_staging;

BEGIN;

DELETE FROM dq_check_result WHERE batch_id IS NULL;

DROP TABLE IF EXISTS pg_temp.dq;
CREATE TEMP TABLE dq (
    check_category TEXT, check_name TEXT, target_table TEXT,
    expected_value NUMERIC, actual_value NUMERIC, warn_only BOOLEAN DEFAULT FALSE, details TEXT
);


-- 1. Integrity: orphan foreign keys (fact/bridge rows without a matching dimension row)

DROP TABLE IF EXISTS pg_temp.fk_list;
CREATE TEMP TABLE fk_list (child_table TEXT, child_column TEXT, parent_table TEXT, parent_column TEXT);
INSERT INTO fk_list VALUES
    ('fact_vulnerability_intelligence_snapshot', 'assessment_date_key',    'dim_date',       'date_key'),
    ('fact_vulnerability_intelligence_snapshot', 'published_date_key',     'dim_date',       'date_key'),
    ('fact_vulnerability_intelligence_snapshot', 'last_modified_date_key', 'dim_date',       'date_key'),
    ('fact_vulnerability_intelligence_snapshot', 'kev_date_added_key',     'dim_date',       'date_key'),
    ('fact_vulnerability_intelligence_snapshot', 'kev_due_date_key',       'dim_date',       'date_key'),
    ('fact_vulnerability_intelligence_snapshot', 'cve_key',                'dim_cve',        'cve_key'),
    ('fact_vulnerability_intelligence_snapshot', 'cvss_key',               'dim_cvss',       'cvss_key'),
    ('fact_vulnerability_intelligence_snapshot', 'kev_status_key',         'dim_kev_status', 'kev_status_key'),
    ('fact_vulnerability_intelligence_snapshot', 'risk_band_key',          'dim_risk_band',  'risk_band_key'),
    ('fact_asset_software_inventory_snapshot',   'snapshot_date_key',      'dim_date',       'date_key'),
    ('fact_asset_software_inventory_snapshot',   'asset_key',              'dim_asset',      'asset_key'),
    ('fact_asset_software_inventory_snapshot',   'software_key',           'dim_software',   'software_key'),
    ('fact_asset_vulnerability_exposure',        'assessment_date_key',    'dim_date',       'date_key'),
    ('fact_asset_vulnerability_exposure',        'remediation_due_date_key','dim_date',      'date_key'),
    ('fact_asset_vulnerability_exposure',        'first_detected_date_key','dim_date',       'date_key'),
    ('fact_asset_vulnerability_exposure',        'cve_key',                'dim_cve',        'cve_key'),
    ('fact_asset_vulnerability_exposure',        'asset_key',              'dim_asset',      'asset_key'),
    ('fact_asset_vulnerability_exposure',        'software_key',           'dim_software',   'software_key'),
    ('fact_asset_vulnerability_exposure',        'product_key',            'dim_product',    'product_key'),
    ('fact_asset_vulnerability_exposure',        'cvss_key',               'dim_cvss',       'cvss_key'),
    ('fact_asset_vulnerability_exposure',        'kev_status_key',         'dim_kev_status', 'kev_status_key'),
    ('fact_asset_vulnerability_exposure',        'risk_band_key',          'dim_risk_band',  'risk_band_key'),
    ('bridge_cve_product',                       'cve_key',                'dim_cve',        'cve_key'),
    ('bridge_cve_product',                       'product_key',            'dim_product',    'product_key'),
    ('bridge_cve_cwe',                           'cve_key',                'dim_cve',        'cve_key'),
    ('bridge_cve_cwe',                           'cwe_key',                'dim_cwe',        'cwe_key'),
    ('bridge_product_software_map',              'product_key',            'dim_product',    'product_key'),
    ('bridge_product_software_map',              'software_key',           'dim_software',   'software_key');

DO $$
DECLARE
    r        RECORD;
    v_orphan BIGINT;
    v_total  BIGINT;
    v_unknown BIGINT;
BEGIN
    FOR r IN SELECT * FROM fk_list LOOP
        EXECUTE format(
            'SELECT count(*) FILTER (WHERE p.%4$I IS NULL), count(*), count(*) FILTER (WHERE c.%2$I = -1)
             FROM project_dw.%1$I c LEFT JOIN project_dw.%3$I p ON p.%4$I = c.%2$I',
            r.child_table, r.child_column, r.parent_table, r.parent_column)
        INTO v_orphan, v_total, v_unknown;

        INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
        VALUES ('Integrity', 'Rows without matching ' || r.parent_table || ' (' || r.child_column || ')', r.child_table,
                0, v_orphan, v_total || ' rows checked');

        IF v_unknown > 0 THEN
            INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
            VALUES ('Integrity', 'Rows pointing at the Unknown member (' || r.child_column || ' = -1)', r.child_table,
                    0, v_unknown, TRUE,
                    round(100.0 * v_unknown / v_total, 2) || '% of ' || v_total
                    || ' rows - value missing in the source or not applicable (e.g. KEV dates of a CVE that is not in KEV)');
        END IF;
    END LOOP;
END $$;


-- 2. Uniqueness

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'CVEs with more than one current row', 'dim_cve', 0, count(*), 'SCD2: exactly one is_current row per cve_id'
FROM (SELECT cve_id FROM dim_cve WHERE is_current GROUP BY cve_id HAVING count(*) > 1) x;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'CVEs with no current row', 'dim_cve', 0, count(*), 'every cve_id must have a current version'
FROM (SELECT cve_id FROM dim_cve GROUP BY cve_id HAVING count(*) FILTER (WHERE is_current) = 0) x;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'Overlapping SCD2 date ranges', 'dim_cve', 0, count(*), 'versions of the same CVE whose effective ranges overlap'
FROM dim_cve a JOIN dim_cve b
  ON a.cve_id = b.cve_id AND a.cve_key < b.cve_key
 AND a.effective_start_date <= b.effective_end_date AND b.effective_start_date <= a.effective_end_date;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'Assets with more than one current row', 'dim_asset', 0, count(*), 'SCD2: exactly one is_current row per asset_id'
FROM (SELECT asset_id FROM dim_asset WHERE is_current GROUP BY asset_id HAVING count(*) > 1) x;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'Overlapping SCD2 date ranges', 'dim_asset', 0, count(*), 'versions of the same asset whose effective ranges overlap'
FROM dim_asset a JOIN dim_asset b
  ON a.asset_id = b.asset_id AND a.asset_key < b.asset_key
 AND a.effective_start_date <= b.effective_end_date AND b.effective_start_date <= a.effective_end_date;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'Duplicate natural keys', t, 0, n, k
FROM (
    SELECT 'dim_product' AS t, 'vendor:product' AS k, count(*) - count(DISTINCT vendor_product_name) AS n FROM dim_product
    UNION ALL SELECT 'dim_cwe', 'cwe_code', count(*) - count(DISTINCT cwe_code) FROM dim_cwe
    UNION ALL SELECT 'dim_software', 'software name + version', count(*) - count(DISTINCT (normalized_software_name, software_version)) FROM dim_software
    UNION ALL SELECT 'dim_date', 'full_date', count(full_date) - count(DISTINCT full_date) FROM dim_date
) x;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Uniqueness', 'Duplicate rows at the declared grain', t, 0, n, g
FROM (
    SELECT 'fact_vulnerability_intelligence_snapshot' AS t, 'CVE x snapshot date' AS g,
           count(*) - count(DISTINCT (f.assessment_date_key, c.cve_id)) AS n
    FROM fact_vulnerability_intelligence_snapshot f JOIN dim_cve c ON c.cve_key = f.cve_key
    UNION ALL
    SELECT 'fact_asset_software_inventory_snapshot', 'asset x software x snapshot date',
           count(*) - count(DISTINCT (f.snapshot_date_key, a.asset_id, f.software_key))
    FROM fact_asset_software_inventory_snapshot f JOIN dim_asset a ON a.asset_key = f.asset_key
    UNION ALL
    SELECT 'fact_asset_vulnerability_exposure', 'CVE x asset x software x assessment date',
           count(*) - count(DISTINCT (f.assessment_date_key, c.cve_id, a.asset_id, f.software_key))
    FROM fact_asset_vulnerability_exposure f
    JOIN dim_cve c ON c.cve_key = f.cve_key JOIN dim_asset a ON a.asset_key = f.asset_key
) x;


-- 3. Validity

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'EPSS outside 0-1 (BR-02)', 'fact_vulnerability_intelligence_snapshot', 0,
       count(*) FILTER (WHERE epss_score NOT BETWEEN 0 AND 1 OR epss_percentile NOT BETWEEN 0 AND 1), count(*) || ' rows checked'
FROM fact_vulnerability_intelligence_snapshot;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'CVSS outside 0-10 (BR-03)', 'dim_cvss', 0,
       count(*) FILTER (WHERE base_score NOT BETWEEN 0 AND 10), count(*) || ' rows checked'
FROM dim_cvss;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'KEV due date before date added (BR-05)', 'cur_kev_catalog', 0,
       count(*) FILTER (WHERE due_date < date_added), count(*) || ' KEV entries checked'
FROM cur_kev_catalog;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'Asset criticality outside Critical/High/Medium/Low (BR-06)', 'dim_asset', 0,
       count(*) FILTER (WHERE criticality_level NOT IN ('Critical', 'High', 'Medium', 'Low')), count(*) || ' asset rows checked'
FROM dim_asset WHERE asset_key > 0;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'Risk band does not match the risk score', t, 0, n, 'score must fall inside the band''s min/max'
FROM (
    SELECT 'fact_vulnerability_intelligence_snapshot' AS t,
           count(*) FILTER (WHERE f.vulnerability_risk_score NOT BETWEEN b.minimum_score AND b.maximum_score) AS n
    FROM fact_vulnerability_intelligence_snapshot f JOIN dim_risk_band b USING (risk_band_key)
    UNION ALL
    SELECT 'fact_asset_vulnerability_exposure',
           count(*) FILTER (WHERE f.risk_priority_score NOT BETWEEN b.minimum_score AND b.maximum_score)
    FROM fact_asset_vulnerability_exposure f JOIN dim_risk_band b USING (risk_band_key)
) x;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'days_to_kev_due_date <> KEV due date - assessment date', 'fact_vulnerability_intelligence_snapshot', 0,
       count(*) FILTER (WHERE f.days_to_kev_due_date IS DISTINCT FROM (dd.full_date - ad.full_date)),
       count(*) || ' KEV rows checked'
FROM fact_vulnerability_intelligence_snapshot f
JOIN dim_date ad ON ad.date_key = f.assessment_date_key
JOIN dim_date dd ON dd.date_key = f.kev_due_date_key
WHERE f.kev_listed_flag = 1;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Validity', 'KEV flag disagrees with dim_kev_status', t, 0, n, 'kev_listed_flag vs dim_kev_status.is_kev_listed'
FROM (
    SELECT 'fact_vulnerability_intelligence_snapshot' AS t,
           count(*) FILTER (WHERE (f.kev_listed_flag = 1) <> k.is_kev_listed) AS n
    FROM fact_vulnerability_intelligence_snapshot f JOIN dim_kev_status k USING (kev_status_key)
    UNION ALL
    SELECT 'fact_asset_vulnerability_exposure', count(*) FILTER (WHERE (f.kev_listed_flag = 1) <> k.is_kev_listed)
    FROM fact_asset_vulnerability_exposure f JOIN dim_kev_status k USING (kev_status_key)
) x;


-- 4. Completeness

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Loaded batches with a vulnerability snapshot', 'fact_vulnerability_intelligence_snapshot',
       (SELECT count(*) FROM etl_batch_log WHERE status = 'Success'),
       (SELECT count(DISTINCT assessment_date_key) FROM fact_vulnerability_intelligence_snapshot),
       'one snapshot date per successfully loaded batch';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Loaded batches with an inventory snapshot', 'fact_asset_software_inventory_snapshot',
       (SELECT count(*) FROM etl_batch_log WHERE status = 'Success'),
       (SELECT count(DISTINCT snapshot_date_key) FROM fact_asset_software_inventory_snapshot),
       'one snapshot date per successfully loaded batch';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'KEV CVEs not (yet) in the NVD feed', 'cur_kev_catalog', 0, count(*), TRUE,
       'KEV entries whose CVE has no NVD record loaded - they cannot be snapshotted; '
       || (SELECT count(*) FROM cur_kev_catalog) || ' KEV entries in total'
FROM cur_kev_catalog k
WHERE NOT EXISTS (SELECT 1 FROM dim_cve d WHERE d.cve_id = k.cve_id);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'Current CVEs without an English description', 'dim_cve', 0,
       count(*) FILTER (WHERE description_en = 'No English description available'), TRUE,
       count(*) || ' current CVEs; missing descriptions were filled with a default text'
FROM dim_cve WHERE is_current AND cve_key > 0;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'Current CVEs without a CWE', 'dim_cve', 0,
       count(*) FILTER (WHERE primary_cwe_code IS NULL), TRUE,
       count(*) || ' current CVEs; NVD has not assigned a weakness yet'
FROM dim_cve WHERE is_current AND cve_key > 0;

-- Phase 2 volume targets: dimension 100+ records, fact 10,000+ records
INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Phase 2 target: at least 100 dimension records', t,
       100, least(n, 100), n || ' rows'
FROM (
    SELECT 'dim_cve' AS t, count(*) AS n FROM dim_cve WHERE cve_key > 0
    UNION ALL SELECT 'dim_asset', count(*) FROM dim_asset WHERE asset_key > 0
    UNION ALL SELECT 'dim_product', count(*) FROM dim_product WHERE product_key > 0
    UNION ALL SELECT 'dim_date', count(*) FROM dim_date WHERE date_key > 0
) x;

-- a volume target, not a data defect: WARN when only a sample of batches is loaded
INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'Phase 2 target: at least 10,000 fact records', t,
       10000, least(n, 10000), TRUE,
       n || ' rows from ' || (SELECT count(*) FROM etl_batch_log WHERE status = 'Success') || ' loaded batches'
FROM (
    SELECT 'fact_vulnerability_intelligence_snapshot' AS t, count(*) AS n FROM fact_vulnerability_intelligence_snapshot
    UNION ALL SELECT 'fact_asset_vulnerability_exposure', count(*) FROM fact_asset_vulnerability_exposure
) x;


-- 5. Accuracy: exposure measures agree with the CVE snapshot of the same date

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'Exposure EPSS / CVSS / KEV equal the snapshot of the same CVE and date', 'fact_asset_vulnerability_exposure',
       0,
       count(*) FILTER (WHERE e.epss_score IS DISTINCT FROM v.epss_score
                           OR e.cvss_base_score IS DISTINCT FROM v.cvss_base_score
                           OR e.kev_listed_flag <> v.kev_listed_flag
                           OR v.cve_key IS NULL),
       count(*) || ' exposure rows checked'
FROM fact_asset_vulnerability_exposure e
LEFT JOIN fact_vulnerability_intelligence_snapshot v
       ON v.cve_key = e.cve_key AND v.assessment_date_key = e.assessment_date_key;

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'Exposure rows whose asset is not in the inventory snapshot of that date', 'fact_asset_vulnerability_exposure',
       0, count(*), 'every exposure must come from installed software'
FROM fact_asset_vulnerability_exposure e
WHERE NOT EXISTS (SELECT 1 FROM fact_asset_software_inventory_snapshot i
                  WHERE i.snapshot_date_key = e.assessment_date_key
                    AND i.asset_key = e.asset_key AND i.software_key = e.software_key);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'Confirmed exposures whose version is not in the affected range', 'fact_asset_vulnerability_exposure',
       0,
       count(*) FILTER (WHERE NOT EXISTS (
           SELECT 1 FROM bridge_cve_product b
           WHERE b.cve_key = e.cve_key AND b.product_key = e.product_key
             AND fn_version_in_range(s.software_version, b.cpe_version, b.version_start_including,
                                     b.version_start_excluding, b.version_end_including, b.version_end_excluding))),
       count(*) || ' confirmed exposures of the latest date re-checked'
FROM fact_asset_vulnerability_exposure e
JOIN dim_software s ON s.software_key = e.software_key
WHERE e.match_confidence = 'Confirmed'
  AND e.assessment_date_key = (SELECT max(assessment_date_key) FROM fact_asset_vulnerability_exposure);


INSERT INTO dq_check_result (batch_id, check_category, check_name, target_table, expected_value, actual_value, status, details)
SELECT NULL, check_category, check_name, target_table, expected_value, actual_value,
       CASE WHEN expected_value = actual_value THEN 'PASS' WHEN warn_only THEN 'WARN' ELSE 'FAIL' END,
       details
FROM dq;

COMMIT;

\pset footer off
SELECT check_category, status, count(*) AS checks
FROM dq_check_result WHERE batch_id IS NULL
GROUP BY 1, 2 ORDER BY 1, 2;

SELECT check_category, check_name, target_table, expected_value, actual_value, details
FROM dq_check_result
WHERE batch_id IS NULL AND status <> 'PASS'
ORDER BY status, check_category;
