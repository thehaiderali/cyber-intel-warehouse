/*
   test_06_data_quality.sql
   Comprehensive data quality checks across the warehouse.

   What is tested
     1. Completeness       : no NULL values in critical columns
     2. Uniqueness         : business keys are unique where expected
     3. Validity           : data values fall within expected ranges
     4. Consistency        : related data is consistent across tables
     5. Referential integrity : no orphan foreign keys
     6. Data freshness     : recent data exists in fact tables

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_06_data_quality.sql
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
    -- 1. Completeness - critical columns should not be NULL
    PERFORM pg_temp.expect_true('completeness', 'dim_cve has no NULL cve_id in current rows',
           (SELECT count(*) = 0 FROM dim_cve WHERE is_current AND cve_id IS NULL),
           (SELECT count(*) || ' NULL cve_id found' FROM dim_cve WHERE is_current AND cve_id IS NULL));

    PERFORM pg_temp.expect_true('completeness', 'dim_asset has no NULL asset_id in current rows',
           (SELECT count(*) = 0 FROM dim_asset WHERE is_current AND asset_id IS NULL),
           (SELECT count(*) || ' NULL asset_id found' FROM dim_asset WHERE is_current AND asset_id IS NULL));

    PERFORM pg_temp.expect_true('completeness', 'dim_product has no NULL vendor_product_name',
           (SELECT count(*) = 0 FROM dim_product WHERE vendor_product_name IS NULL),
           (SELECT count(*) || ' NULL vendor_product_name found' FROM dim_product WHERE vendor_product_name IS NULL));

    PERFORM pg_temp.expect_true('completeness', 'dim_date has no NULL full_date for valid keys',
           (SELECT count(*) = 0 FROM dim_date WHERE date_key > 0 AND full_date IS NULL),
           (SELECT count(*) || ' NULL full_date found' FROM dim_date WHERE date_key > 0 AND full_date IS NULL));

    -- 2. Uniqueness - business keys should be unique
    PERFORM pg_temp.expect_true('uniqueness', 'cve_id is unique among current rows',
           (SELECT count(*) = 0 FROM dim_cve WHERE is_current GROUP BY cve_id HAVING count(*) > 1),
           'duplicate cve_id found');

    PERFORM pg_temp.expect_true('uniqueness', 'asset_id is unique among current rows',
           (SELECT count(*) = 0 FROM dim_asset WHERE is_current GROUP BY asset_id HAVING count(*) > 1),
           'duplicate asset_id found');

    PERFORM pg_temp.expect_true('uniqueness', 'vendor_product_name is unique',
           (SELECT count(*) = 0 FROM dim_product GROUP BY vendor_product_name HAVING count(*) > 1),
           'duplicate vendor_product_name found');

    PERFORM pg_temp.expect_true('uniqueness', 'cwe_code is unique',
           (SELECT count(*) = 0 FROM dim_cwe GROUP BY cwe_code HAVING count(*) > 1),
           'duplicate cwe_code found');

    -- 3. Validity - scores and dates in valid ranges
    PERFORM pg_temp.expect_true('validity', 'cvss_base_score between 0 and 10',
           (SELECT count(*) = 0 FROM dim_cvss WHERE cvss_base_score IS NOT NULL
            AND (cvss_base_score < 0 OR cvss_base_score > 10)),
           (SELECT count(*) || ' invalid CVSS scores' FROM dim_cvss WHERE cvss_base_score IS NOT NULL
            AND (cvss_base_score < 0 OR cvss_base_score > 10)));

    PERFORM pg_temp.expect_true('validity', 'epss_score between 0 and 1',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot
            WHERE epss_score IS NOT NULL AND (epss_score < 0 OR epss_score > 1)),
           (SELECT count(*) || ' invalid EPSS scores' FROM fact_vulnerability_intelligence_snapshot
            WHERE epss_score IS NOT NULL AND (epss_score < 0 OR epss_score > 1)));

    PERFORM pg_temp.expect_true('validity', 'vulnerability_risk_score between 0 and 100',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot
            WHERE vulnerability_risk_score IS NOT NULL
            AND (vulnerability_risk_score < 0 OR vulnerability_risk_score > 100)),
           (SELECT count(*) || ' invalid risk scores' FROM fact_vulnerability_intelligence_snapshot
            WHERE vulnerability_risk_score IS NOT NULL
            AND (vulnerability_risk_score < 0 OR vulnerability_risk_score > 100)));

    PERFORM pg_temp.expect_true('validity', 'date keys in valid format (YYYYMMDD)',
           (SELECT count(*) = 0 FROM dim_date
            WHERE date_key > 0 AND date_key NOT BETWEEN 19700101 AND 20991231),
           (SELECT count(*) || ' invalid date keys' FROM dim_date
            WHERE date_key > 0 AND date_key NOT BETWEEN 19700101 AND 20991231));

    -- 4. Consistency - SCD Type 2 effective dates
    PERFORM pg_temp.expect_true('consistency', 'effective_end_date >= effective_start_date',
           (SELECT count(*) = 0 FROM dim_cve
            WHERE effective_end_date IS NOT NULL AND effective_end_date < effective_start_date),
           (SELECT count(*) || ' invalid date ranges' FROM dim_cve
            WHERE effective_end_date IS NOT NULL AND effective_end_date < effective_start_date));

    PERFORM pg_temp.expect_true('consistency', 'effective_end_date is NULL for current rows',
           (SELECT count(*) = 0 FROM dim_cve WHERE is_current AND effective_end_date IS NOT NULL),
           (SELECT count(*) || ' current rows with end date' FROM dim_cve WHERE is_current AND effective_end_date IS NOT NULL));

    PERFORM pg_temp.expect_true('consistency', 'effective_end_date is set for non-current rows',
           (SELECT count(*) = 0 FROM dim_cve WHERE NOT is_current AND effective_end_date IS NULL),
           (SELECT count(*) || ' non-current rows without end date' FROM dim_cve WHERE NOT is_current AND effective_end_date IS NULL));

    -- 5. Referential integrity - no orphan foreign keys
    PERFORM pg_temp.expect_true('referential integrity', 'no orphan cve_key in fact_vulnerability',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_cve d ON f.cve_key = d.cve_key WHERE d.cve_key IS NULL),
           (SELECT count(*) || ' orphan cve_key' FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_cve d ON f.cve_key = d.cve_key WHERE d.cve_key IS NULL));

    PERFORM pg_temp.expect_true('referential integrity', 'no orphan cvss_key in fact_vulnerability',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_cvss d ON f.cvss_key = d.cvss_key WHERE d.cvss_key IS NULL),
           (SELECT count(*) || ' orphan cvss_key' FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_cvss d ON f.cvss_key = d.cvss_key WHERE d.cvss_key IS NULL));

    PERFORM pg_temp.expect_true('referential integrity', 'no orphan asset_key in fact_exposure',
           (SELECT count(*) = 0 FROM fact_asset_vulnerability_exposure f
            LEFT JOIN dim_asset d ON f.asset_key = d.asset_key WHERE d.asset_key IS NULL),
           (SELECT count(*) || ' orphan asset_key' FROM fact_asset_vulnerability_exposure f
            LEFT JOIN dim_asset d ON f.asset_key = d.asset_key WHERE d.asset_key IS NULL));

    PERFORM pg_temp.expect_true('referential integrity', 'no orphan date_key in fact_vulnerability',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_date d ON f.assessment_date_key = d.date_key WHERE d.date_key IS NULL),
           (SELECT count(*) || ' orphan assessment_date_key' FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_date d ON f.assessment_date_key = d.date_key WHERE d.date_key IS NULL));

    -- 6. Data freshness - fact tables should have recent data
    PERFORM pg_temp.expect_true('freshness', 'fact_vulnerability has data',
           (SELECT count(*) > 0 FROM fact_vulnerability_intelligence_snapshot),
           'no data in fact_vulnerability_intelligence_snapshot');

    PERFORM pg_temp.expect_true('freshness', 'fact_exposure has data',
           (SELECT count(*) > 0 FROM fact_asset_vulnerability_exposure),
           'no data in fact_asset_vulnerability_exposure');

    PERFORM pg_temp.expect_true('freshness', 'fact_inventory has data',
           (SELECT count(*) > 0 FROM fact_asset_software_inventory_snapshot),
           'no data in fact_asset_software_inventory_snapshot');

    -- 7. Data quality metrics
    PERFORM pg_temp.expect_true('quality metrics', 'high percentage of current CVEs',
           (SELECT CASE WHEN count(*) = 0 THEN TRUE
            ELSE (count(*) FILTER (WHERE is_current)::NUMERIC / count(*) > 0.5) END
            FROM dim_cve),
           'less than 50% of CVEs are current');

    PERFORM pg_temp.expect_true('quality metrics', 'high percentage of current assets',
           (SELECT CASE WHEN count(*) = 0 THEN TRUE
            ELSE (count(*) FILTER (WHERE is_current)::NUMERIC / count(*) > 0.5) END
            FROM dim_asset),
           'less than 50% of assets are current');

    -- 8. ETL audit log
    PERFORM pg_temp.expect_true('audit log', 'etl_batch_log exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'etl_batch_log')),
           'etl_batch_log not found');

    PERFORM pg_temp.expect_true('audit log', 'etl_batch_log has entries',
           (SELECT count(*) > 0 FROM project_staging.etl_batch_log),
           'no batch records in etl_batch_log');

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
        RAISE EXCEPTION '% of % data quality tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % data quality tests passed', v_total;
END $$;
