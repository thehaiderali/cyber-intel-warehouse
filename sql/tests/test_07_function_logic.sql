/*
   test_07_function_logic.sql
   Comprehensive tests for all custom database functions.

   What is tested
     1. Text cleaning        : fn_clean_text handles spaces, placeholders, case
     2. Version comparison   : fn_version_compare handles all version formats
     3. Version range        : fn_version_in_range matches correctly
     4. Date key conversion  : fn_date_key converts dates properly
     5. Risk score formulas  : fn_exposure_risk_score, fn_cve_risk_score
     6. Edge cases          : NULL handling, boundary conditions

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_07_function_logic.sql
*/

SET client_min_messages = warning;
SET LOCAL search_path = project_dw, project_staging;

CREATE TEMP TABLE test_result (
    test_no     INT GENERATED ALWAYS AS IDENTITY,
    test_group  TEXT,
    test_name   TEXT,
    passed      BOOLEAN,
    detail      TEXT
) ON COMMIT DROP;

CREATE FUNCTION pg_temp.check(p_group TEXT, p_name TEXT, p_actual ANYELEMENT, p_expected ANYELEMENT) RETURNS VOID AS $$
    INSERT INTO test_result (test_group, test_name, passed, detail)
    VALUES (p_group, p_name, p_actual IS NOT DISTINCT FROM p_expected,
            CASE WHEN p_actual IS DISTINCT FROM p_expected
                 THEN 'expected ' || coalesce(p_expected::TEXT, 'NULL') || ', got ' || coalesce(p_actual::TEXT, 'NULL') END);
$$ LANGUAGE sql;

DO $tests$
BEGIN
    -- 1. Text cleaning function
    PERFORM pg_temp.check('clean_text', 'basic trim', fn_clean_text('  test  '), 'test');
    PERFORM pg_temp.check('clean_text', 'collapse multiple spaces', fn_clean_text('test   multiple   spaces'), 'test multiple spaces');
    PERFORM pg_temp.check('clean_text', 'trim leading spaces', fn_clean_text('   leading'), 'leading');
    PERFORM pg_temp.check('clean_text', 'trim trailing spaces', fn_clean_text('trailing   '), 'trailing');
    PERFORM pg_temp.check('clean_text', 'placeholder N/A to NULL', fn_clean_text('N/A'), NULL);
    PERFORM pg_temp.check('clean_text', 'placeholder n/a to NULL', fn_clean_text('n/a'), NULL);
    PERFORM pg_temp.check('clean_text', 'placeholder NULL to NULL', fn_clean_text('NULL'), NULL);
    PERFORM pg_temp.check('clean_text', 'placeholder null to NULL', fn_clean_text('null'), NULL);
    PERFORM pg_temp.check('clean_text', 'placeholder NONE to NULL', fn_clean_text('NONE'), NULL);
    PERFORM pg_temp.check('clean_text', 'empty string to NULL', fn_clean_text(''), NULL);
    PERFORM pg_temp.check('clean_text', 'only spaces to NULL', fn_clean_text('   '), NULL);
    PERFORM pg_temp.check('clean_text', 'preserve case', fn_clean_text('Test Case'), 'Test Case');
    PERFORM pg_temp.check('clean_text', 'handle special chars', fn_clean_text('test-v1.0_2024'), 'test-v1.0_2024');

    -- 2. Version comparison function
    PERFORM pg_temp.check('version_compare', '1.0 < 2.0', fn_version_compare('1.0', '2.0'), -1);
    PERFORM pg_temp.check('version_compare', '2.0 > 1.0', fn_version_compare('2.0', '1.0'), 1);
    PERFORM pg_temp.check('version_compare', '1.0 = 1.0', fn_version_compare('1.0', '1.0'), 0);
    PERFORM pg_temp.check('version_compare', '2.4.49 < 2.4.50', fn_version_compare('2.4.49', '2.4.50'), -1);
    PERFORM pg_temp.check('version_compare', '2.4.9 < 2.4.49 (numeric)', fn_version_compare('2.4.9', '2.4.49'), -1);
    PERFORM pg_temp.check('version_compare', '10.0 > 9.9', fn_version_compare('10.0', '9.9'), 1);
    PERFORM pg_temp.check('version_compare', '8.0 = 8.0.0', fn_version_compare('8.0', '8.0.0'), 0);
    PERFORM pg_temp.check('version_compare', '9.6p1 > 9.6', fn_version_compare('9.6p1', '9.6'), 1);
    PERFORM pg_temp.check('version_compare', '1.0-rc1 < 1.0', fn_version_compare('1.0-rc1', '1.0'), -1);
    PERFORM pg_temp.check('version_compare', '2019 = 2019', fn_version_compare('2019', '2019'), 0);
    PERFORM pg_temp.check('version_compare', 'case insensitive', fn_version_compare('1.0.0-RC1', '1.0.0-rc1'), 0);
    PERFORM pg_temp.check('version_compare', '1.0.0 > 1.0', fn_version_compare('1.0.0', '1.0'), 1);
    PERFORM pg_temp.check('version_compare', '1.0.0.0 = 1.0.0', fn_version_compare('1.0.0.0', '1.0.0'), 0);
    PERFORM pg_temp.check('version_compare', '1.0.0.1 > 1.0.0', fn_version_compare('1.0.0.1', '1.0.0'), 1);

    -- 3. Version range matching function
    PERFORM pg_temp.check('version_range', 'exact match', fn_version_in_range('2.4.49', '2.4.49', NULL, NULL, NULL, NULL), TRUE);
    PERFORM pg_temp.check('version_range', 'exact mismatch', fn_version_in_range('2.4.58', '2.4.49', NULL, NULL, NULL, NULL), FALSE);
    PERFORM pg_temp.check('version_range', 'inside inclusive range', fn_version_in_range('2.4.49', NULL, '2.4.0', NULL, NULL, '2.4.51'), TRUE);
    PERFORM pg_temp.check('version_range', 'outside range', fn_version_in_range('2.4.60', NULL, '2.4.0', NULL, NULL, '2.4.51'), FALSE);
    PERFORM pg_temp.check('version_range', 'end exclusive', fn_version_in_range('2.4.51', NULL, '2.4.0', NULL, NULL, '2.4.51'), FALSE);
    PERFORM pg_temp.check('version_range', 'end inclusive', fn_version_in_range('2.4.51', NULL, NULL, NULL, '2.4.51', NULL), TRUE);
    PERFORM pg_temp.check('version_range', 'start exclusive', fn_version_in_range('5.0.0', NULL, NULL, '5.0.0', '6.0.0', NULL), FALSE);
    PERFORM pg_temp.check('version_range', 'below start inclusive', fn_version_in_range('1.9', NULL, '2.0', NULL, NULL, '3.0'), FALSE);
    PERFORM pg_temp.check('version_range', 'no version info -> NULL', fn_version_in_range('8.0.0', NULL, NULL, NULL, NULL, NULL), NULL);
    PERFORM pg_temp.check('version_range', 'above end inclusive', fn_version_in_range('3.1', NULL, NULL, NULL, '3.0', NULL), FALSE);
    PERFORM pg_temp.check('version_range', 'complex range', fn_version_in_range('2.4.49', NULL, '2.4.0', '2.4.0', '2.5.0', '2.5.0'), TRUE);

    -- 4. Date key conversion function
    PERFORM pg_temp.check('date_key', 'YYYYMMDD format', fn_date_key(DATE '2026-10-08'), 20261008);
    PERFORM pg_temp.check('date_key', 'NULL -> -1', fn_date_key(NULL), -1);
    PERFORM pg_temp.check('date_key', 'out of calendar -> -1', fn_date_key(DATE '1970-01-01'), -1);
    PERFORM pg_temp.check('date_key', 'min valid date', fn_date_key(DATE '1900-01-01'), 19000101);
    PERFORM pg_temp.check('date_key', 'max valid date', fn_date_key(DATE '2099-12-31'), 20991231);
    PERFORM pg_temp.check('date_key', 'leap year', fn_date_key(DATE '2024-02-29'), 20240229);
    PERFORM pg_temp.check('date_key', 'year boundary', fn_date_key(DATE '2026-01-01'), 20260101);
    PERFORM pg_temp.check('date_key', 'month boundary', fn_date_key(DATE '2026-12-31'), 20261231);

    -- 5. Exposure risk score function
    -- Formula: (CVSS/10*35) + (EPSS*30) + 20 + (criticality/4*10) + (internet_exposed*5)
    -- Max: 35 + 30 + 20 + 10 + 5 = 100
    PERFORM pg_temp.check('exposure_score', 'max score', fn_exposure_risk_score(10, 1, 1, 4, 1), 100.00::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'min score (no KEV, low criticality, internal)',
           fn_exposure_risk_score(0, 0, 0, 1, 0), 2.50::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'medium CVSS, high EPSS',
           fn_exposure_risk_score(7.5, 0.8, 0, 2, 0), 58.25::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'NULL CVSS/EPSS handling',
           fn_exposure_risk_score(NULL, NULL, 0, 1, 0), 2.50::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'high CVSS only',
           fn_exposure_risk_score(9.8, 0, 0, 1, 0), 54.30::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'KEV only',
           fn_exposure_risk_score(0, 0, 1, 1, 0), 22.50::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'critical asset only',
           fn_exposure_risk_score(0, 0, 0, 4, 0), 32.50::NUMERIC(6,2));
    PERFORM pg_temp.check('exposure_score', 'internet exposed only',
           fn_exposure_risk_score(0, 0, 0, 1, 1), 27.50::NUMERIC(6,2));

    -- 6. CVE risk score function
    -- Formula: (CVSS/10*35 + EPSS*30 + 20) / 85 * 100
    -- Max: (35 + 30 + 20) / 85 * 100 = 100
    PERFORM pg_temp.check('cve_score', 'max score', fn_cve_risk_score(10, 1, 1), 100.00::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'min score (no KEV)',
           fn_cve_risk_score(0, 0, 0), 23.53::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'NULL CVSS/EPSS handling',
           fn_cve_risk_score(NULL, NULL, 0), 23.53::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'high CVSS only',
           fn_cve_risk_score(9.8, 0, 0), 56.24::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'high EPSS only',
           fn_cve_risk_score(0, 0.94, 0), 51.76::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'KEV only',
           fn_cve_risk_score(0, 0, 1), 23.53::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'balanced high risk',
           fn_cve_risk_score(9.8, 0.94, 1), 97.06::NUMERIC(6,2));
    PERFORM pg_temp.check('cve_score', 'medium risk',
           fn_cve_risk_score(5.5, 0.3, 0), 45.41::NUMERIC(6,2));

    -- 7. Edge cases and NULL handling
    PERFORM pg_temp.check('edge cases', 'version_compare with NULL v1', fn_version_compare(NULL, '1.0'), NULL);
    PERFORM pg_temp.check('edge cases', 'version_compare with NULL v2', fn_version_compare('1.0', NULL), NULL);
    PERFORM pg_temp.check('edge cases', 'version_compare both NULL', fn_version_compare(NULL, NULL), NULL);
    PERFORM pg_temp.check('edge cases', 'clean_text with NULL', fn_clean_text(NULL), NULL);
    PERFORM pg_temp.check('edge cases', 'exposure_score all NULL',
           fn_exposure_risk_score(NULL, NULL, NULL, NULL, NULL), 2.50::NUMERIC(6,2));
    PERFORM pg_temp.check('edge cases', 'cve_score all NULL',
           fn_cve_risk_score(NULL, NULL, NULL), 23.53::NUMERIC(6,2));

    -- 8. Boundary conditions
    PERFORM pg_temp.check('boundaries', 'CVSS at 0', fn_exposure_risk_score(0, 0.5, 0, 2, 0), 17.50::NUMERIC(6,2));
    PERFORM pg_temp.check('boundaries', 'CVSS at 10', fn_exposure_risk_score(10, 0.5, 0, 2, 0), 52.50::NUMERIC(6,2));
    PERFORM pg_temp.check('boundaries', 'EPSS at 0', fn_exposure_risk_score(5, 0, 0, 2, 0), 40.00::NUMERIC(6,2));
    PERFORM pg_temp.check('boundaries', 'EPSS at 1', fn_exposure_risk_score(5, 1, 0, 2, 0), 70.00::NUMERIC(6,2));
    PERFORM pg_temp.check('boundaries', 'criticality at 1', fn_exposure_risk_score(5, 0.5, 0, 1, 0), 35.00::NUMERIC(6,2));
    PERFORM pg_temp.check('boundaries', 'criticality at 4', fn_exposure_risk_score(5, 0.5, 0, 4, 0), 42.50::NUMERIC(6,2));

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
        RAISE EXCEPTION '% of % function logic tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % function logic tests passed', v_total;
END $$;
