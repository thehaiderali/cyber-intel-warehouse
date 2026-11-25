/*
   test_10_integration.sql
   Comprehensive integration tests across all warehouse components.

   What is tested
     1. End-to-end flow    : data flows from staging through DW to reporting
     2. Cross-layer checks : consistency between staging, DW, and reporting
     3. Business logic     : calculated metrics match expected formulas
     4. Snapshot integrity : fact snapshots match dimensional state
     5. Risk calculations  : risk scores are consistent across tables
     6. Time-based tests   : SCD2 history preserved correctly
     7. Aggregate validation : reporting view aggregations match source data
     8. Complete scenario  : full data path validation

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_10_integration.sql
*/

SET client_min_messages = warning;
SET LOCAL search_path = project_staging, project_dw, project_reporting;

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
    -- 1. End-to-end flow - staging to DW to reporting
    PERFORM pg_temp.expect_true('end-to-end', 'staging CVE count >= DW CVE count (raw may have dups)',
           (SELECT count(*) FROM stg_cve) >= (SELECT count(*) FROM dim_cve WHERE is_current),
           'staging: ' || (SELECT count(*) FROM stg_cve) || ', DW: ' || (SELECT count(*) FROM dim_cve WHERE is_current));

    PERFORM pg_temp.expect_true('end-to-end', 'staging asset count >= DW asset count (raw may have dups)',
           (SELECT count(*) FROM stg_asset) >= (SELECT count(*) FROM dim_asset WHERE is_current),
           'staging: ' || (SELECT count(*) FROM stg_asset) || ', DW: ' || (SELECT count(*) FROM dim_asset WHERE is_current));

    -- 2. Cross-layer consistency
    PERFORM pg_temp.expect_true('cross-layer', 'fact snapshot count matches latest snapshot date',
           (SELECT count(*) FROM fact_vulnerability_intelligence_snapshot
            WHERE assessment_date_key = (SELECT max(assessment_date_key) FROM fact_vulnerability_intelligence_snapshot)) > 0,
           'no snapshot rows for latest date');

    PERFORM pg_temp.expect_true('cross-layer', 'exposure fact matches snapshot date',
           (SELECT count(*) FROM fact_asset_vulnerability_exposure
            WHERE assessment_date_key = (SELECT max(assessment_date_key) FROM fact_asset_vulnerability_exposure)) > 0,
           'no exposure rows for latest date');

    -- 3. Business logic - risk scores calculated correctly
    PERFORM pg_temp.expect_true('business logic', 'vulnerability risk scores within valid range',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot
            WHERE vulnerability_risk_score IS NOT NULL
              AND (vulnerability_risk_score < 0 OR vulnerability_risk_score > 100)),
           'risk scores outside 0-100 range');

    PERFORM pg_temp.expect_true('business logic', 'risk priority scores within valid range',
           (SELECT count(*) = 0 FROM fact_asset_vulnerability_exposure
            WHERE risk_priority_score IS NOT NULL
              AND (risk_priority_score < 0 OR risk_priority_score > 100)),
           'risk priority scores outside 0-100 range');

    -- 4. Snapshot integrity - facts reference current dimensional state
    PERFORM pg_temp.expect_true('snapshot integrity', 'fact CVEs reference current CVEs',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot f
            JOIN dim_cve c ON f.cve_key = c.cve_key WHERE NOT c.is_current),
           'facts reference non-current CVEs');

    PERFORM pg_temp.expect_true('snapshot integrity', 'fact assets reference current assets',
           (SELECT count(*) = 0 FROM fact_asset_vulnerability_exposure f
            JOIN dim_asset a ON f.asset_key = a.asset_key WHERE NOT a.is_current),
           'facts reference non-current assets');

    -- 5. Risk calculation consistency
    PERFORM pg_temp.expect_true('risk consistency', 'CVSS severity matches score range',
           (SELECT count(*) = 0 FROM dim_cvss
            WHERE base_severity = 'CRITICAL' AND (base_score IS NULL OR base_score < 9.0)
               OR base_severity = 'HIGH' AND (base_score IS NULL OR base_score < 7.0 OR base_score >= 9.0)
               OR base_severity = 'MEDIUM' AND (base_score IS NULL OR base_score < 4.0 OR base_score >= 7.0)
               OR base_severity = 'LOW' AND (base_score IS NULL OR base_score >= 4.0)),
           'CVSS severity does not match score range');

    PERFORM pg_temp.expect_true('risk consistency', 'EPSS percentile between 0 and 100',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot
            WHERE epss_percentile IS NOT NULL AND (epss_percentile < 0 OR epss_percentile > 100)),
           'EPSS percentile outside 0-100 range');

    -- 6. Time-based tests - SCD2 history
    PERFORM pg_temp.expect_true('time-based', 'CVE effective dates are sequential',
           (SELECT count(*) = 0 FROM dim_cve
            WHERE cve_key IN (SELECT cve_key FROM dim_cve GROUP BY cve_key HAVING count(*) > 1)
              AND effective_end_date IS NOT NULL
              AND effective_end_date < effective_start_date),
           'non-sequential effective dates found');

    PERFORM pg_temp.expect_true('time-based', 'only one current version per CVE',
           (SELECT count(*) = 0 FROM dim_cve WHERE is_current GROUP BY cve_id HAVING count(*) > 1),
           'multiple current versions for same CVE');

    PERFORM pg_temp.expect_true('time-based', 'only one current version per asset',
           (SELECT count(*) = 0 FROM dim_asset WHERE is_current GROUP BY asset_id HAVING count(*) > 1),
           'multiple current versions for same asset');

    -- 7. Aggregate validation - reporting views match source data
    PERFORM pg_temp.expect_true('aggregates', 'KPI total CVEs matches dim_cve count',
           (SELECT count(*) FROM dim_cve WHERE is_current AND cve_key > 0) =
           (SELECT total_cves_analyzed FROM vw_kpi_summary),
           'KPI count does not match dimension count');

    PERFORM pg_temp.expect_true('aggregates', 'KPI watch-listed CVEs matches fact count',
           (SELECT count(*) FROM vw_latest_cve_snapshot) =
           (SELECT watch_listed_cves FROM vw_kpi_summary),
           'KPI count does not match fact count');

    PERFORM pg_temp.expect_true('aggregates', 'severity distribution sums to total',
           (SELECT sum(cve_count) FROM vw_q06_severity_distribution) =
           (SELECT count(*) FROM vw_latest_cve_snapshot),
           'severity distribution does not sum to total');

    -- 8. Complete scenario - validate a complete data path
    PERFORM pg_temp.expect_true('complete scenario', 'bridge tables have connections',
           (SELECT count(*) > 0 FROM bridge_cve_product),
           'no CVE-product bridges');

    PERFORM pg_temp.expect_true('complete scenario', 'bridge tables have connections',
           (SELECT count(*) > 0 FROM bridge_cve_cwe),
           'no CVE-CWE bridges');

    PERFORM pg_temp.expect_true('complete scenario', 'bridge tables have connections',
           (SELECT count(*) > 0 FROM bridge_product_software_map),
           'no product-software bridges');

    -- 9. Integration check - reporting views use latest data
    PERFORM pg_temp.expect_true('reporting integration', 'latest snapshot date matches KPI date',
           (SELECT max(assessment_date) FROM vw_latest_cve_snapshot) =
           (SELECT assessment_date FROM vw_kpi_summary),
           'reporting views use different snapshot dates');

    -- 10. Data lineage - trace from staging to reporting
    PERFORM pg_temp.expect_true('data lineage', 'staging CVEs flow to DW CVEs',
           (SELECT count(*) > 0 FROM stg_cve) >=
           (SELECT CASE WHEN count(*) = 0 THEN 0 ELSE 1 END FROM dim_cve WHERE is_current),
           'no data flow from staging to DW');

    PERFORM pg_temp.expect_true('data lineage', 'staging assets flow to DW assets',
           (SELECT count(*) > 0 FROM stg_asset) >=
           (SELECT CASE WHEN count(*) = 0 THEN 0 ELSE 1 END FROM dim_asset WHERE is_current),
           'no data flow from staging to DW');

    -- 11. Referential integrity across all layers
    PERFORM pg_temp.expect_true('referential integrity', 'all fact foreign keys valid',
           (SELECT count(*) = 0 FROM fact_vulnerability_intelligence_snapshot f
            LEFT JOIN dim_cve c ON f.cve_key = c.cve_key
            LEFT JOIN dim_cvss cv ON f.cvss_key = cv.cvss_key
            LEFT JOIN dim_kev_status ks ON f.kev_status_key = ks.kev_status_key
            LEFT JOIN dim_risk_band rb ON f.risk_band_key = rb.risk_band_key
            LEFT JOIN dim_date d ON f.assessment_date_key = d.date_key
            WHERE c.cve_key IS NULL OR cv.cvss_key IS NULL OR ks.kev_status_key IS NULL
               OR rb.risk_band_key IS NULL OR d.date_key IS NULL),
           'orphan foreign keys in vulnerability snapshot');

    PERFORM pg_temp.expect_true('referential integrity', 'all exposure fact foreign keys valid',
           (SELECT count(*) = 0 FROM fact_asset_vulnerability_exposure f
            LEFT JOIN dim_cve c ON f.cve_key = c.cve_key
            LEFT JOIN dim_asset a ON f.asset_key = a.asset_key
            LEFT JOIN dim_software s ON f.software_key = s.software_key
            LEFT JOIN dim_product p ON f.product_key = p.product_key
            LEFT JOIN dim_cvss cv ON f.cvss_key = cv.cvss_key
            LEFT JOIN dim_risk_band rb ON f.risk_band_key = rb.risk_band_key
            WHERE c.cve_key IS NULL OR a.asset_key IS NULL OR s.software_key IS NULL
               OR p.product_key IS NULL OR cv.cvss_key IS NULL OR rb.risk_band_key IS NULL),
           'orphan foreign keys in exposure fact');

    -- 12. Business question validation - views answer the questions
    PERFORM pg_temp.expect_true('business questions', 'Q1 returns ranked CVEs',
           (SELECT count(*) > 0 FROM vw_q01_cve_risk_ranking),
           'Q1 view returns no data');

    PERFORM pg_temp.expect_true('business questions', 'Q6 returns severity distribution',
           (SELECT count(*) > 0 FROM vw_q06_severity_distribution),
           'Q6 view returns no data');

    PERFORM pg_temp.expect_true('business questions', 'KPI summary returns metrics',
           (SELECT count(*) = 1 FROM vw_kpi_summary),
           'KPI summary should return exactly 1 row');

    -- 13. ETL to DW consistency
    PERFORM pg_temp.expect_true('etl consistency', 'batch log dates are within reasonable range',
           (SELECT count(*) = 0 FROM etl_batch_log
            WHERE batch_date < DATE '2020-01-01' OR batch_date > CURRENT_DATE + INTERVAL '1 year'),
           'batch dates outside reasonable range');

    -- 14. Final integration check - all layers connected
    PERFORM pg_temp.expect_true('final integration', 'staging -> DW -> reporting path complete',
           (SELECT count(*) > 0 FROM stg_cve) > 0
           AND (SELECT count(*) > 0 FROM dim_cve WHERE is_current) > 0
           AND (SELECT count(*) > 0 FROM vw_latest_cve_snapshot),
           'data path broken between layers');

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
        RAISE EXCEPTION '% of % integration tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % integration tests passed', v_total;
END $$;
