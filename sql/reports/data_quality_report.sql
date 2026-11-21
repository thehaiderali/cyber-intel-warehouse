/*
   data_quality_report.sql
   Builds the Data Quality Report as HTML from project_staging.dq_check_result.
   Run:  psql -U postgres -d intel_dw -q -f sql/reports/data_quality_report.sql -o reports/Data_Quality_Report.html
   Then print the HTML to PDF (see README).
*/
\pset format html
\pset footer off
\pset tableattr 'border="1" cellpadding="4" style="border-collapse:collapse;font-size:11px"'
\qecho '<html><head><meta charset="utf-8"><title>Data Quality Report</title><style>body{font-family:Arial,sans-serif;margin:28px;font-size:12px} h1{font-size:22px} h2{font-size:15px;margin-top:22px} th{background:#e8eef5}</style></head><body>'
\qecho '<h1>Data Quality Report</h1>'
\qecho '<p>DL3004 Phase 2 - Cyber Intel Warehouse. Afras Shahnawaz (24L-2547), Rana Nauman Iqbal (24L-2565), Haider Ali (24L-2522).</p>'
\qecho '<p>Checks are SQL scripts <code>sql/dq/70_dq_batch_checks.sql</code> (every batch) and <code>sql/dq/71_dq_warehouse_checks.sql</code> (whole warehouse). PASS = expected value equals actual value; WARN = known gap in the source data (not a load defect); FAIL = load defect.</p>'

\qecho '<h2>1. Summary</h2>'
SELECT check_category, count(*) AS checks,
       count(*) FILTER (WHERE status = 'PASS') AS pass,
       count(*) FILTER (WHERE status = 'WARN') AS warn,
       count(*) FILTER (WHERE status = 'FAIL') AS fail
FROM project_staging.dq_check_result
GROUP BY check_category ORDER BY check_category;

\qecho '<h2>2. Warehouse contents</h2>'
SELECT 'dim_cve (all versions)' AS table_name, count(*) AS rows FROM project_dw.dim_cve WHERE cve_key > 0
UNION ALL SELECT 'dim_asset', count(*) FROM project_dw.dim_asset WHERE asset_key > 0
UNION ALL SELECT 'dim_product', count(*) FROM project_dw.dim_product WHERE product_key > 0
UNION ALL SELECT 'dim_software', count(*) FROM project_dw.dim_software WHERE software_key > 0
UNION ALL SELECT 'dim_cvss', count(*) FROM project_dw.dim_cvss WHERE cvss_key > 0
UNION ALL SELECT 'dim_cwe', count(*) FROM project_dw.dim_cwe WHERE cwe_key > 0
UNION ALL SELECT 'dim_kev_status', count(*) FROM project_dw.dim_kev_status WHERE kev_status_key > 0
UNION ALL SELECT 'dim_date', count(*) FROM project_dw.dim_date WHERE date_key > 0
UNION ALL SELECT 'bridge_cve_product', count(*) FROM project_dw.bridge_cve_product
UNION ALL SELECT 'bridge_cve_cwe', count(*) FROM project_dw.bridge_cve_cwe
UNION ALL SELECT 'bridge_product_software_map', count(*) FROM project_dw.bridge_product_software_map
UNION ALL SELECT 'fact_vulnerability_intelligence_snapshot', count(*) FROM project_dw.fact_vulnerability_intelligence_snapshot
UNION ALL SELECT 'fact_asset_software_inventory_snapshot', count(*) FROM project_dw.fact_asset_software_inventory_snapshot
UNION ALL SELECT 'fact_asset_vulnerability_exposure', count(*) FROM project_dw.fact_asset_vulnerability_exposure;

\qecho '<h2>3. Integrity - fact / bridge rows without a matching dimension row (must be 0)</h2>'
SELECT target_table, check_name, expected_value AS expected, actual_value AS actual, status, details
FROM project_staging.dq_check_result
WHERE batch_id IS NULL AND check_category = 'Integrity' ORDER BY status DESC, target_table, check_name;

\qecho '<h2>4. Accuracy - reconciliation and recomputation (per batch and warehouse-wide)</h2>'
SELECT coalesce(batch_id, 'warehouse') AS scope, check_name, expected_value AS expected, actual_value AS actual, status
FROM project_staging.dq_check_result
WHERE check_category = 'Accuracy' ORDER BY scope, check_name;

\qecho '<h2>5. Completeness - source rows = staged + rejected, missing values</h2>'
SELECT coalesce(batch_id, 'warehouse') AS scope, check_name, target_table, expected_value AS expected, actual_value AS actual, status, details
FROM project_staging.dq_check_result
WHERE check_category = 'Completeness' ORDER BY scope, check_name;

\qecho '<h2>6. Uniqueness and validity</h2>'
SELECT check_category, check_name, target_table, expected_value AS expected, actual_value AS actual, status, details
FROM project_staging.dq_check_result
WHERE check_category IN ('Uniqueness', 'Validity') ORDER BY check_category, check_name;

\qecho '<h2>7. Findings</h2>'
SELECT status, check_name, target_table, actual_value AS actual, details
FROM project_staging.dq_check_result
WHERE status <> 'PASS' ORDER BY status, check_name;
\qecho '<p>All WARN rows are gaps in the public source data (e.g. KEV CVEs not yet in the NVD sample, CVEs NVD has not classified) or the volume target, which is met when all incremental batches are loaded with sql/run/load_all_batches.sql. No FAIL results means every load reconciled and every foreign key resolved.</p>'
\qecho '</body></html>'
