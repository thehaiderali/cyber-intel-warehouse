/*
   70_dq_batch_checks.sql
   Data quality checks run at the end of every batch (inside the batch
   transaction, while the batch's staging data is still available).
   Results go to project_staging.dq_check_result.

   Completeness  every source record is either staged or rejected (row reconciliation);
                 every staged CVE / asset reached its dimension;
                 missing EPSS / CVSS values in today's facts
   Accuracy      EPSS and CVSS reconciliation (source sum = fact sum);
                 KEV count reconciliation; risk scores recomputed from the formula
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.dq;
CREATE TEMP TABLE dq (
    check_category TEXT, check_name TEXT, target_table TEXT,
    expected_value NUMERIC, actual_value NUMERIC, warn_only BOOLEAN DEFAULT FALSE, details TEXT
);


-- Completeness: row reconciliation source -> staging + quarantine

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'NVD records = staged + rejected', 'stg_cve',
       (SELECT coalesce(sum(jsonb_array_length(document -> 'vulnerabilities')), 0) FROM raw_nvd_document),
       (SELECT count(*) FROM stg_cve)
     + (SELECT count(*) FROM stg_reject WHERE batch_id = :'batch_id' AND source_name = 'NVD' AND rule_id <> 'BR-03'),
       'raw records vs stg_cve + stg_reject';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'EPSS rows = staged + rejected', 'stg_epss',
       (SELECT count(*) FROM raw_epss),
       (SELECT count(*) FROM stg_epss)
     + (SELECT count(*) FROM stg_reject WHERE batch_id = :'batch_id' AND source_name = 'EPSS'),
       'raw_epss vs stg_epss + stg_reject';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'KEV entries = staged + rejected', 'stg_kev',
       (SELECT coalesce(sum(jsonb_array_length(document -> 'vulnerabilities')), 0) FROM raw_kev_document),
       (SELECT count(*) FROM stg_kev)
     + (SELECT count(*) FROM stg_reject WHERE batch_id = :'batch_id' AND source_name = 'KEV'),
       'raw entries vs stg_kev + stg_reject';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Asset rows = staged + rejected', 'stg_asset',
       (SELECT count(*) FROM raw_asset),
       (SELECT count(*) FROM stg_asset)
     + (SELECT count(*) FROM stg_reject WHERE batch_id = :'batch_id' AND source_name = 'ASSET' AND rule_id <> 'DQ-FMT'),
       'raw_asset vs stg_asset + stg_reject (field fixes excluded)'
WHERE EXISTS (SELECT 1 FROM raw_asset);


-- Completeness: staging -> dimensions

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Every staged CVE has a current dim_cve row', 'dim_cve',
       (SELECT count(*) FROM stg_cve),
       (SELECT count(*) FROM stg_cve s JOIN dim_cve d ON d.cve_id = s.cve_id AND d.is_current),
       'staged CVEs vs CVEs found in dim_cve';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Every staged asset has a current dim_asset row', 'dim_asset',
       (SELECT count(*) FROM stg_asset),
       (SELECT count(*) FROM stg_asset s JOIN dim_asset d ON d.asset_id = s.asset_id AND d.is_current),
       'staged assets vs assets found in dim_asset'
WHERE EXISTS (SELECT 1 FROM stg_asset);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Every staged CPE match is in bridge_cve_product', 'bridge_cve_product',
       (SELECT count(*) FROM stg_cve_cpe),
       (SELECT count(*) FROM stg_cve_cpe s
        JOIN dim_cve d ON d.cve_id = s.cve_id AND d.is_current
        JOIN dim_product p ON p.vendor_name = s.cpe_vendor AND p.product_name = s.cpe_product
        JOIN bridge_cve_product b ON b.cve_key = d.cve_key AND b.product_key = p.product_key
                                 AND b.cpe_criteria = s.cpe_criteria
                                 AND b.version_start_including IS NOT DISTINCT FROM s.version_start_including
                                 AND b.version_start_excluding IS NOT DISTINCT FROM s.version_start_excluding
                                 AND b.version_end_including   IS NOT DISTINCT FROM s.version_end_including
                                 AND b.version_end_excluding   IS NOT DISTINCT FROM s.version_end_excluding),
       'staged CPE rows vs bridge rows';


-- Completeness: missing values in today's facts (warnings - the source has gaps)

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'Snapshot rows without an EPSS score', 'fact_vulnerability_intelligence_snapshot',
       0, count(*) FILTER (WHERE epss_score IS NULL), TRUE,
       round(100.0 * count(*) FILTER (WHERE epss_score IS NULL) / nullif(count(*), 0), 2) || '% of ' || count(*) || ' rows'
FROM fact_vulnerability_intelligence_snapshot
WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, warn_only, details)
SELECT 'Completeness', 'Snapshot rows without a CVSS score', 'fact_vulnerability_intelligence_snapshot',
       0, count(*) FILTER (WHERE cvss_key = -1), TRUE,
       round(100.0 * count(*) FILTER (WHERE cvss_key = -1) / nullif(count(*), 0), 2) || '% of ' || count(*) || ' rows'
FROM fact_vulnerability_intelligence_snapshot
WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Completeness', 'Inventory snapshot covers every current asset', 'fact_asset_software_inventory_snapshot',
       (SELECT count(*) FROM dim_asset WHERE is_current AND asset_key > 0),
       (SELECT count(DISTINCT asset_key) FROM fact_asset_software_inventory_snapshot
        WHERE snapshot_date_key = fn_date_key(:'batch_date'::DATE)),
       'current assets vs assets in today''s inventory snapshot';


-- Accuracy: reconciliation of measures (the "revenue reconciliation" of this warehouse)

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'EPSS reconciliation: SUM(stg_epss) = SUM(snapshot epss_score)', 'fact_vulnerability_intelligence_snapshot',
       (SELECT coalesce(sum(e.epss_score), 0)
        FROM stg_epss e
        JOIN dim_cve d ON d.cve_id = e.cve_id AND d.is_current
        JOIN fact_vulnerability_intelligence_snapshot f
          ON f.cve_key = d.cve_key AND f.assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       (SELECT coalesce(sum(epss_score), 0) FROM fact_vulnerability_intelligence_snapshot
        WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       'sum of EPSS over the snapshot CVEs, source vs fact';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'CVSS reconciliation: SUM(latest CVSS) = SUM(snapshot cvss_base_score)', 'fact_vulnerability_intelligence_snapshot',
       (SELECT coalesce(sum(s.cvss_base_score), 0)
        FROM cur_cve_score s
        JOIN dim_cve d ON d.cve_id = s.cve_id AND d.is_current
        JOIN fact_vulnerability_intelligence_snapshot f
          ON f.cve_key = d.cve_key AND f.assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       (SELECT coalesce(sum(cvss_base_score), 0) FROM fact_vulnerability_intelligence_snapshot
        WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       'sum of CVSS over the snapshot CVEs, source vs fact';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'KEV reconciliation: KEV CVEs known to NVD = KEV rows in snapshot', 'fact_vulnerability_intelligence_snapshot',
       (SELECT count(*) FROM cur_kev_catalog k
        JOIN dim_cve d ON d.cve_id = k.cve_id AND d.is_current AND d.vulnerability_status IS DISTINCT FROM 'Rejected'),
       (SELECT coalesce(sum(kev_listed_flag), 0) FROM fact_vulnerability_intelligence_snapshot
        WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       'KEV catalog CVEs present in dim_cve vs SUM(kev_listed_flag)';

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'Snapshot risk score matches the formula', 'fact_vulnerability_intelligence_snapshot',
       0,
       count(*) FILTER (WHERE vulnerability_risk_score <>
           round((coalesce(cvss_base_score, 0) * 3.5 + coalesce(epss_score, 0) * 30 + kev_listed_flag * 20) * 100 / 85, 2)),
       'rows where (CVSS/10*35 + EPSS*30 + KEV*20)*100/85 differs from the stored score'
FROM fact_vulnerability_intelligence_snapshot
WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE);

INSERT INTO dq (check_category, check_name, target_table, expected_value, actual_value, details)
SELECT 'Accuracy', 'Exposure risk score matches the Phase 1 formula', 'fact_asset_vulnerability_exposure',
       0,
       count(*) FILTER (WHERE risk_priority_score <>
           round(coalesce(cvss_base_score, 0) * 3.5 + coalesce(epss_score, 0) * 30 + kev_listed_flag * 20
                 + asset_criticality_score * 2.5 + internet_exposed_flag * 5, 2)),
       'rows where CVSS/10*35 + EPSS*30 + KEV*20 + criticality/4*10 + exposed*5 differs from the stored score'
FROM fact_asset_vulnerability_exposure
WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE);


INSERT INTO dq_check_result (batch_id, check_category, check_name, target_table, expected_value, actual_value, status, details)
SELECT :'batch_id', check_category, check_name, target_table, expected_value, actual_value,
       CASE WHEN expected_value = actual_value THEN 'PASS'
            WHEN warn_only THEN 'WARN'
            ELSE 'FAIL' END,
       details
FROM dq;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, status, message)
SELECT :'batch_id', 'quality', 'Batch data quality checks', 'dq_check_result', count(*),
       count(*) FILTER (WHERE expected_value = actual_value),
       CASE WHEN count(*) FILTER (WHERE expected_value <> actual_value AND NOT warn_only) = 0 THEN 'Success' ELSE 'Failed' END,
       format('%s PASS, %s WARN, %s FAIL',
              count(*) FILTER (WHERE expected_value = actual_value),
              count(*) FILTER (WHERE expected_value <> actual_value AND warn_only),
              count(*) FILTER (WHERE expected_value <> actual_value AND NOT warn_only))
FROM dq;

DROP TABLE dq;
