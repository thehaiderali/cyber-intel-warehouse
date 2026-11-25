/*
   test_05_reference_data.sql
   Reference data and controlled value validation tests.

   What is tested
     1. Reference tables      : ref_controlled_value, ref_software_cpe_map exist
     2. Controlled values     : location, environment, criticality domains populated
     3. Standardization       : mapping logic works for common values
     4. Software mapping      : CPE mapping table has entries
     5. Risk bands            : risk band table configured with thresholds
     6. Date dimension        : dim_date has necessary date range

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_05_reference_data.sql
*/

SET client_min_messages = warning;
SET LOCAL search_path = project_staging, project_dw;

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
    -- 1. Reference tables exist
    PERFORM pg_temp.expect_true('reference tables', 'ref_controlled_value exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'ref_controlled_value')),
           'table not found');

    PERFORM pg_temp.expect_true('reference tables', 'ref_software_cpe_map exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'ref_software_cpe_map')),
           'table not found');

    -- 2. Controlled value domains
    PERFORM pg_temp.expect_true('controlled values', 'location domain exists',
           (SELECT EXISTS (SELECT 1 FROM ref_controlled_value WHERE domain = 'location')),
           'location domain not found');

    PERFORM pg_temp.expect_true('controlled values', 'environment domain exists',
           (SELECT EXISTS (SELECT 1 FROM ref_controlled_value WHERE domain = 'environment')),
           'environment domain not found');

    PERFORM pg_temp.expect_true('controlled values', 'criticality domain exists',
           (SELECT EXISTS (SELECT 1 FROM ref_controlled_value WHERE domain = 'criticality')),
           'criticality domain not found');

    PERFORM pg_temp.expect_true('controlled values', 'department domain exists',
           (SELECT EXISTS (SELECT 1 FROM ref_controlled_value WHERE domain = 'department')),
           'department domain not found');

    PERFORM pg_temp.expect_true('controlled values', 'software_name domain exists',
           (SELECT EXISTS (SELECT 1 FROM ref_controlled_value WHERE domain = 'software_name')),
           'software_name domain not found');

    -- 3. Common location mappings
    PERFORM pg_temp.expect_true('location mapping', 'lahore maps to Lahore',
           (SELECT standard_value = 'Lahore' FROM ref_controlled_value
            WHERE domain = 'location' AND source_value = 'lahore'),
           'mapping incorrect');

    PERFORM pg_temp.expect_true('location mapping', 'isb maps to Islamabad',
           (SELECT standard_value = 'Islamabad' FROM ref_controlled_value
            WHERE domain = 'location' AND source_value = 'isb'),
           'mapping incorrect');

    -- 4. Environment mappings
    PERFORM pg_temp.expect_true('environment mapping', 'prod maps to Production',
           (SELECT standard_value = 'Production' FROM ref_controlled_value
            WHERE domain = 'environment' AND source_value = 'prod'),
           'mapping incorrect');

    PERFORM pg_temp.expect_true('environment mapping', 'dev maps to Development',
           (SELECT standard_value = 'Development' FROM ref_controlled_value
            WHERE domain = 'environment' AND source_value = 'dev'),
           'mapping incorrect');

    -- 5. Criticality mappings
    PERFORM pg_temp.expect_true('criticality mapping', 'high maps to High',
           (SELECT standard_value = 'High' FROM ref_controlled_value
            WHERE domain = 'criticality' AND source_value = 'high'),
           'mapping incorrect');

    PERFORM pg_temp.expect_true('criticality mapping', 'critical maps to Critical',
           (SELECT standard_value = 'Critical' FROM ref_controlled_value
            WHERE domain = 'criticality' AND source_value = 'critical'),
           'mapping incorrect');

    -- 6. Software name mappings
    PERFORM pg_temp.expect_true('software mapping', 'k8s maps to Kubernetes',
           (SELECT standard_value = 'Kubernetes' FROM ref_controlled_value
            WHERE domain = 'software_name' AND source_value = 'k8s'),
           'mapping incorrect');

    PERFORM pg_temp.expect_true('software mapping', 'mysql maps to MySQL',
           (SELECT standard_value = 'MySQL' FROM ref_controlled_value
            WHERE domain = 'software_name' AND source_value = 'mysql'),
           'mapping incorrect');

    -- 7. CPE mapping table has entries
    PERFORM pg_temp.expect_true('cpe mapping', 'ref_software_cpe_map has entries',
           (SELECT count(*) > 0 FROM ref_software_cpe_map),
           'no CPE mappings found');

    -- 8. Risk bands configured
    PERFORM pg_temp.expect_true('risk bands', 'dim_risk_band exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'dim_risk_band')),
           'dim_risk_band not found');

    PERFORM pg_temp.expect_true('risk bands', 'risk bands have thresholds',
           (SELECT count(*) >= 4 FROM dim_risk_band),
           'insufficient risk bands');

    PERFORM pg_temp.expect_true('risk bands', 'Critical band exists (>= 70)',
           (SELECT EXISTS (SELECT 1 FROM dim_risk_band WHERE risk_band_name = 'Critical' AND minimum_score >= 70)),
           'Critical band not configured correctly');

    PERFORM pg_temp.expect_true('risk bands', 'High band exists (50-69.99)',
           (SELECT EXISTS (SELECT 1 FROM dim_risk_band WHERE risk_band_name = 'High'
            AND minimum_score >= 50 AND maximum_score < 70)),
           'High band not configured correctly');

    PERFORM pg_temp.expect_true('risk bands', 'Medium band exists (30-49.99)',
           (SELECT EXISTS (SELECT 1 FROM dim_risk_band WHERE risk_band_name = 'Medium'
            AND minimum_score >= 30 AND maximum_score < 50)),
           'Medium band not configured correctly');

    PERFORM pg_temp.expect_true('risk bands', 'Low band exists (< 30)',
           (SELECT EXISTS (SELECT 1 FROM dim_risk_band WHERE risk_band_name = 'Low' AND maximum_score < 30)),
           'Low band not configured correctly');

    -- 9. Date dimension has entries
    PERFORM pg_temp.expect_true('date dimension', 'dim_date exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'dim_date')),
           'dim_date not found');

    PERFORM pg_temp.expect_true('date dimension', 'dim_date has unknown member (-1)',
           (SELECT EXISTS (SELECT 1 FROM dim_date WHERE date_key = -1)),
           'unknown member missing');

    PERFORM pg_temp.expect_true('date dimension', 'dim_date has recent dates',
           (SELECT count(*) > 0 FROM dim_date WHERE year_number >= 2020),
           'no recent dates in dim_date');

    -- 10. Unknown members in dimensions
    PERFORM pg_temp.expect_true('unknown members', 'dim_cve has unknown member (-1)',
           (SELECT EXISTS (SELECT 1 FROM dim_cve WHERE cve_key = -1)),
           'unknown member missing in dim_cve');

    PERFORM pg_temp.expect_true('unknown members', 'dim_asset has unknown member (-1)',
           (SELECT EXISTS (SELECT 1 FROM dim_asset WHERE asset_key = -1)),
           'unknown member missing in dim_asset');

    PERFORM pg_temp.expect_true('unknown members', 'dim_cvss has unknown member (-1)',
           (SELECT EXISTS (SELECT 1 FROM dim_cvss WHERE cvss_key = -1)),
           'unknown member missing in dim_cvss');

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
        RAISE EXCEPTION '% of % reference data tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % reference data tests passed', v_total;
END $$;
