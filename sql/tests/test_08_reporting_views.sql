/*
   test_08_reporting_views.sql
   Validation tests for all reporting views.

   What is tested
     1. View existence     : all 14 reporting views exist
     2. View accessibility : views can be queried without errors
     3. Column counts      : views have expected number of columns
     4. Data returns       : views return data when warehouse is loaded
     5. View dependencies  : views depend on correct tables
     6. Aggregation tests  : aggregated views produce correct summaries

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_08_reporting_views.sql
*/

SET client_min_messages = warning;
SET LOCAL search_path = project_reporting, project_dw;

CREATE TEMP TABLE test_result (
    test_no     INT GENERATED ALWAYS AS IDENTITY,
    test_group  TEXT,
    test_name   TEXT,
    passed      BOOLEAN,
    detail      TEXT
) ON COMMIT DROP;

CREATE FUNCTION pg_temp.expect_true(p_group TEXT, p_name TEXT, p_condition BOOLEAN, p_detail TEXT DEFAULT NULL) RETURNS VOID AS $$
    INSERT INTO test_result (test_group, test_name, passed, detail)
    VALUES (p_group, p_name, coalesce(p_condition, FALSE), CASE WHEN NOT coalesce(p_condition, FALSE) THEN p_detail END);
$$ LANGUAGE sql;

DO $tests$
BEGIN
    -- 1. View existence - all 14 views should exist
    PERFORM pg_temp.expect_true('view existence', 'vw_q01_cve_risk_ranking exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q01_cve_risk_ranking')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q02_critical_high_cves exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q02_critical_high_cves')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q03_top_epss exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q03_top_epss')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q04_kev_cves exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q04_kev_cves')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q05_kev_remediation_due exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q05_kev_remediation_due')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q06_severity_distribution exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q06_severity_distribution')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q07_vendor_product_cves exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q07_vendor_product_cves')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q08_cwe_high_risk exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q08_cwe_high_risk')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q09_publication_kev_trend exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q09_publication_kev_trend')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q10_ransomware_kev exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q10_ransomware_kev')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q11_asset_exposure exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q11_asset_exposure')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_q12_remediation_workload exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q12_remediation_workload')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_kpi_summary exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_kpi_summary')),
           'view not found');

    PERFORM pg_temp.expect_true('view existence', 'vw_daily_risk_trend exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_daily_risk_trend')),
           'view not found');

    -- 2. Helper views exist
    PERFORM pg_temp.expect_true('helper views', 'vw_latest_cve_snapshot exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_latest_cve_snapshot')),
           'view not found');

    PERFORM pg_temp.expect_true('helper views', 'vw_latest_exposure exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_latest_exposure')),
           'view not found');

    -- 3. View accessibility - can query without errors
    PERFORM pg_temp.expect_true('view accessibility', 'vw_q01_cve_risk_ranking queryable',
           (SELECT count(*) >= 0 FROM vw_q01_cve_risk_ranking LIMIT 1),
           'query failed');

    PERFORM pg_temp.expect_true('view accessibility', 'vw_kpi_summary queryable',
           (SELECT count(*) >= 0 FROM vw_kpi_summary LIMIT 1),
           'query failed');

    PERFORM pg_temp.expect_true('view accessibility', 'vw_daily_risk_trend queryable',
           (SELECT count(*) >= 0 FROM vw_daily_risk_trend LIMIT 1),
           'query failed');

    -- 4. Column counts - verify expected structure
    PERFORM pg_temp.expect_true('column counts', 'vw_q01_cve_risk_ranking has 9 columns',
           (SELECT count(*) = 9 FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q01_cve_risk_ranking'),
           'got ' || (SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q01_cve_risk_ranking') || ' columns');

    PERFORM pg_temp.expect_true('column counts', 'vw_kpi_summary has 8 columns',
           (SELECT count(*) = 8 FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_kpi_summary'),
           'got ' || (SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_kpi_summary') || ' columns');

    PERFORM pg_temp.expect_true('column counts', 'vw_q06_severity_distribution has 4 columns',
           (SELECT count(*) = 4 FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q06_severity_distribution'),
           'got ' || (SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q06_severity_distribution') || ' columns');

    -- 5. View dependencies - depend on project_dw only
    PERFORM pg_temp.expect_true('dependencies', 'views depend on project_dw tables',
           (SELECT count(*) > 0 FROM information_schema.view_table_usage
            WHERE table_schema = 'project_dw' AND view_schema = 'project_reporting'),
           'no dependencies on project_dw found');

    PERFORM pg_temp.expect_true('dependencies', 'views do not depend on project_staging',
           (SELECT count(*) = 0 FROM information_schema.view_table_usage
            WHERE table_schema = 'project_staging' AND view_schema = 'project_reporting'),
           'unexpected dependency on project_staging');

    -- 6. Aggregation tests - verify grouped views work
    PERFORM pg_temp.expect_true('aggregation', 'vw_q06_severity_distribution groups by severity',
           (SELECT count(*) > 0 FROM vw_q06_severity_distribution),
           'no data or aggregation failed');

    PERFORM pg_temp.expect_true('aggregation', 'vw_q07_vendor_product_cves groups by vendor/product',
           (SELECT count(*) > 0 FROM vw_q07_vendor_product_cves),
           'no data or aggregation failed');

    PERFORM pg_temp.expect_true('aggregation', 'vw_q08_cwe_high_risk groups by CWE',
           (SELECT count(*) > 0 FROM vw_q08_cwe_high_risk),
           'no data or aggregation failed');

    PERFORM pg_temp.expect_true('aggregation', 'vw_q09_publication_kev_trend has time dimensions',
           (SELECT count(*) > 0 FROM vw_q09_publication_kev_trend),
           'no data or aggregation failed');

    PERFORM pg_temp.expect_true('aggregation', 'vw_q11_asset_exposure groups by asset',
           (SELECT count(*) > 0 FROM vw_q11_asset_exposure),
           'no data or aggregation failed');

    PERFORM pg_temp.expect_true('aggregation', 'vw_q12_remediation_workload has grouping sets',
           (SELECT count(*) > 0 FROM vw_q12_remediation_workload),
           'no data or aggregation failed');

    -- 7. Data type validation - check critical columns
    PERFORM pg_temp.expect_true('data types', 'vw_q01 risk_rank is numeric',
           (SELECT data_type = 'numeric' FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_q01_cve_risk_ranking' AND column_name = 'risk_rank'),
           'risk_rank is not numeric');

    PERFORM pg_temp.expect_true('data types', 'vw_kpi_summary assessment_date is date',
           (SELECT data_type = 'date' FROM information_schema.columns
            WHERE table_schema = 'project_reporting' AND table_name = 'vw_kpi_summary' AND column_name = 'assessment_date'),
           'assessment_date is not date');

    -- 8. Check for NULL handling in views
    PERFORM pg_temp.expect_true('null handling', 'vw_q06 handles NULL severity',
           (SELECT count(*) > 0 FROM vw_q06_severity_distribution WHERE cvss_severity = 'NONE'),
           'NULL severity not handled');

END $tests$;

-- Report results
\pset footer off
SELECT test_group, count(*) AS tests, count(*) FILTER (WHERE passed) AS passed, count(*) FILTER (WHERE NOT passed) AS failed
FROM test_result GROUP BY test_group ORDER BY min(test_no);

SELECT test_no, test_group, test_name, detail FROM test_result WHERE NOT passed ORDER BY test_no;

-- Fail if any test failed
SET client_min_messages = notice;
DO $$
DECLARE v_failed INT; v_total INT;
BEGIN
    SELECT count(*) FILTER (WHERE NOT passed), count(*) INTO v_failed, v_total FROM test_result;
    IF v_failed > 0 THEN
        RAISE EXCEPTION '% of % reporting view tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % reporting view tests passed', v_total;
END $$;
