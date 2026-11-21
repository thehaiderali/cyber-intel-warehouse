/*
   data_cleaning_report.sql
   Builds the Data Cleaning Report as HTML from the ETL audit tables.
   Run:  psql -U postgres -d intel_dw -q -f sql/reports/data_cleaning_report.sql -o reports/Data_Cleaning_Report.html
   Then print the HTML to PDF (see README).
*/
\pset format html
\pset footer off
\pset tableattr 'border="1" cellpadding="4" style="border-collapse:collapse;font-size:11px"'
\qecho '<html><head><meta charset="utf-8"><title>Data Cleaning Report</title><style>body{font-family:Arial,sans-serif;margin:28px;font-size:12px} h1{font-size:22px} h2{font-size:15px;margin-top:22px} th{background:#e8eef5}</style></head><body>'
\qecho '<h1>Data Cleaning Report</h1>'
\qecho '<p>DL3004 Phase 2 - Cyber Intel Warehouse. Afras Shahnawaz (24L-2547), Rana Nauman Iqbal (24L-2565), Haider Ali (24L-2522).</p>'
\qecho '<p>Generated from <code>project_staging.etl_step_log</code>, <code>etl_cleaning_stat</code> and <code>stg_reject</code>. Sources: NVD CVE JSON, EPSS CSV, CISA KEV JSON, Cortexa asset inventory CSV plus 130 synthetic assets with deliberately injected dirty values.</p>'

\qecho '<h2>1. Cleaning rules applied</h2>'
\qecho '<ul><li><b>Remove duplicates</b> - one row per business key (asset_id, cve_id, CVE+score date); first/latest record kept, the rest logged as DQ-DUP.</li>'
\qecho '<li><b>Handle NULL values</b> - missing owner/department -> Unassigned; missing description -> default text; invalid IP -> NULL; missing CVSS -> Unknown member (-1); missing business key -> rejected.</li>'
\qecho '<li><b>Standardise text</b> - trim, collapse spaces, controlled-value dictionary (e.g. " lahore " / "LAHORE" -> Lahore, PROD -> Production, k8s -> Kubernetes).</li>'
\qecho '<li><b>Convert data types</b> - text -> DATE / TIMESTAMP / NUMERIC(8,6) / NUMERIC(3,1) / BOOLEAN; software versions stay text (BR-04).</li>'
\qecho '<li><b>Validate business rules</b> - BR-01 CVE ID format, BR-02 EPSS 0-1, BR-03 CVSS 0-10, BR-05 KEV due date >= date added, BR-06 controlled criticality.</li></ul>'

\qecho '<h2>2. Batches loaded</h2>'
SELECT batch_id, batch_date, load_type, status, finished_at - started_at AS duration
FROM project_staging.etl_batch_log ORDER BY batch_date;

\qecho '<h2>3. Row counts per staging step (input / output / rejected)</h2>'
SELECT batch_id, step_name, target_table, rows_in, rows_out, rows_rejected, message
FROM project_staging.etl_step_log
WHERE layer IN ('extract', 'staging')
ORDER BY step_log_id;

\qecho '<h2>4. Values changed by each cleaning rule (with a before / after example)</h2>'
SELECT batch_id, source_name AS source, column_name AS "column", cleaning_rule, rows_affected,
       left(example_before, 60) AS example_before, left(example_after, 60) AS example_after
FROM project_staging.etl_cleaning_stat
ORDER BY source_name, column_name, cleaning_rule, batch_id;

\qecho '<h2>5. Rejected / quarantined records by rule</h2>'
SELECT source_name AS source, rule_id, count(*) AS records, min(reject_reason) AS example_reason
FROM project_staging.stg_reject
GROUP BY source_name, rule_id ORDER BY source_name, rule_id;

\qecho '<h2>6. Example rejected records</h2>'
SELECT source_name AS source, business_key, rule_id, reject_reason
FROM (SELECT *, row_number() OVER (PARTITION BY source_name, rule_id ORDER BY reject_id) AS rn
      FROM project_staging.stg_reject) r
WHERE rn <= 3 ORDER BY source_name, rule_id;

\qecho '<h2>7. Asset inventory before and after cleaning</h2>'
SELECT 'location' AS attribute, location_name AS clean_value, count(*) AS assets FROM project_staging.stg_asset GROUP BY 2
UNION ALL SELECT 'environment', environment, count(*) FROM project_staging.stg_asset GROUP BY 2
UNION ALL SELECT 'criticality', criticality_level, count(*) FROM project_staging.stg_asset GROUP BY 2
ORDER BY 1, 2;
\qecho '<p>Note: stg_asset holds the latest batch with an inventory file (the full load).</p>'
\qecho '</body></html>'
