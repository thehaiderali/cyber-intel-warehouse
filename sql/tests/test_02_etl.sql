/*
   test_02_etl.sql
   Tests for the ETL logic.

   1. Functions   fn_clean_text, fn_version_compare, fn_version_in_range,
                  fn_date_key, risk score formulas
   2. Cleaning    controlled-value standardisation (' lahore ' -> 'Lahore')
   3. SCD Type 2  runs the real dim_asset and dim_cve load scripts on a
                  scenario: new member -> attribute change on a later day ->
                  second change on the same day -> unchanged reload
   4. Fact keys   business key -> surrogate key lookup used by the fact loads

   Runs in one transaction that is rolled back; identity sequences are restored.
   Run from the repository root:
     psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_02_etl.sql
*/

\set ON_ERROR_STOP on
SET client_min_messages = warning;
BEGIN;

CREATE TEMP TABLE saved_sequence ON COMMIT DROP AS
SELECT format('%I.%I', schemaname, sequencename) AS seq, start_value, last_value
FROM pg_sequences WHERE schemaname IN ('project_staging', 'project_dw');

CREATE TEMP TABLE test_result (
    test_no INT GENERATED ALWAYS AS IDENTITY, test_group TEXT, test_name TEXT, passed BOOLEAN, detail TEXT
) ON COMMIT DROP;

CREATE FUNCTION pg_temp.check(p_group TEXT, p_name TEXT, p_actual ANYELEMENT, p_expected ANYELEMENT) RETURNS VOID AS $$
    INSERT INTO test_result (test_group, test_name, passed, detail)
    VALUES (p_group, p_name, p_actual IS NOT DISTINCT FROM p_expected,
            CASE WHEN p_actual IS DISTINCT FROM p_expected
                 THEN 'expected ' || coalesce(p_expected::TEXT, 'NULL') || ', got ' || coalesce(p_actual::TEXT, 'NULL') END);
$$ LANGUAGE sql;

SET LOCAL search_path = project_dw, project_staging;


-- 1. Functions

DO $tests$
BEGIN
    PERFORM pg_temp.check('function', 'clean_text trims and collapses spaces', fn_clean_text('  lahore   dc '), 'lahore dc'::TEXT);
    PERFORM pg_temp.check('function', 'clean_text turns placeholders into NULL', fn_clean_text(' N/A '), NULL::TEXT);
    PERFORM pg_temp.check('function', 'clean_text turns blank into NULL', fn_clean_text('   '), NULL::TEXT);

    PERFORM pg_temp.check('function', 'version 2.4.49 < 2.4.50',  fn_version_compare('2.4.49', '2.4.50'), -1);
    PERFORM pg_temp.check('function', 'version 2.4.9 < 2.4.49 (numeric, not text)', fn_version_compare('2.4.9', '2.4.49'), -1);
    PERFORM pg_temp.check('function', 'version 10.0 > 9.9',       fn_version_compare('10.0', '9.9'), 1);
    PERFORM pg_temp.check('function', 'version 8.0 = 8.0.0',      fn_version_compare('8.0', '8.0.0'), 0);
    PERFORM pg_temp.check('function', 'version 9.6p1 > 9.6',      fn_version_compare('9.6p1', '9.6'), 1);
    PERFORM pg_temp.check('function', 'version 1.0-rc1 < 1.0',    fn_version_compare('1.0-rc1', '1.0'), -1);
    PERFORM pg_temp.check('function', 'version 2019 = 2019',      fn_version_compare('2019', '2019'), 0);
    PERFORM pg_temp.check('function', 'version compare is case-insensitive', fn_version_compare('1.0.0-RC1', '1.0.0-rc1'), 0);

    PERFORM pg_temp.check('function', 'exact pin matches',          fn_version_in_range('2.4.49', '2.4.49', NULL, NULL, NULL, NULL), TRUE);
    PERFORM pg_temp.check('function', 'exact pin does not match',   fn_version_in_range('2.4.58', '2.4.49', NULL, NULL, NULL, NULL), FALSE);
    PERFORM pg_temp.check('function', 'inside [2.4.0, 2.4.51)',     fn_version_in_range('2.4.49', NULL, '2.4.0', NULL, NULL, '2.4.51'), TRUE);
    PERFORM pg_temp.check('function', 'end excluding is exclusive', fn_version_in_range('2.4.51', NULL, '2.4.0', NULL, NULL, '2.4.51'), FALSE);
    PERFORM pg_temp.check('function', 'end including is inclusive', fn_version_in_range('2.4.51', NULL, NULL, NULL, '2.4.51', NULL), TRUE);
    PERFORM pg_temp.check('function', 'start excluding is exclusive', fn_version_in_range('5.0.0', NULL, NULL, '5.0.0', '6.0.0', NULL), FALSE);
    PERFORM pg_temp.check('function', 'below start including',      fn_version_in_range('1.9', NULL, '2.0', NULL, NULL, '3.0'), FALSE);
    PERFORM pg_temp.check('function', 'no version information -> NULL', fn_version_in_range('8.0.0', NULL, NULL, NULL, NULL, NULL), NULL::BOOLEAN);

    PERFORM pg_temp.check('function', 'date key YYYYMMDD',          fn_date_key(DATE '2026-10-08'), 20261008);
    PERFORM pg_temp.check('function', 'date key NULL -> -1',        fn_date_key(NULL), -1);
    PERFORM pg_temp.check('function', 'date key out of calendar -> -1', fn_date_key(DATE '1970-01-01'), -1);

    -- Phase 1 example: CVSS 9.8, EPSS 0.94, KEV, critical (4), internet-facing
    -- 9.8/10*35 + 0.94*30 + 20 + 4/4*10 + 5 = 34.3 + 28.2 + 20 + 10 + 5 = 97.5
    PERFORM pg_temp.check('function', 'exposure risk score (Phase 1 formula)', fn_exposure_risk_score(9.8, 0.94, 1, 4, 1), 97.50::NUMERIC(6,2));
    PERFORM pg_temp.check('function', 'exposure risk score with missing CVSS/EPSS', fn_exposure_risk_score(NULL, NULL, 0, 1, 0), 2.50::NUMERIC(6,2));
    -- (34.3 + 28.2 + 20) / 85 * 100 = 97.06
    PERFORM pg_temp.check('function', 'CVE risk score rescaled to 0-100', fn_cve_risk_score(9.8, 0.94, 1), 97.06::NUMERIC(6,2));
    PERFORM pg_temp.check('function', 'maximum CVE risk score is 100', fn_cve_risk_score(10, 1, 1), 100.00::NUMERIC(6,2));
END $tests$;


-- 2. Controlled-value standardisation (the ' lahore ' -> 'Lahore' rule)

DO $$ BEGIN
    PERFORM pg_temp.check('cleaning', '"' || v || '" -> ' || expected,
       (SELECT standard_value FROM ref_controlled_value WHERE domain = d AND source_value = lower(fn_clean_text(v)))::TEXT,
       expected)
FROM (VALUES ('location', ' lahore ', 'Lahore'), ('location', 'LAHORE', 'Lahore'), ('location', 'ISB', 'Islamabad'),
             ('environment', 'PROD', 'Production'), ('environment', ' dev ', 'Development'),
             ('criticality', '  high ', 'High'), ('department', 'FINANCE', 'Finance'),
             ('software_name', 'k8s', 'Kubernetes'), ('software_name', ' mysql ', 'MySQL')) AS t(d, v, expected);
END $$;


-- 3. SCD Type 2 with the real load scripts

INSERT INTO etl_batch_log (batch_id, batch_date, load_type) VALUES
    ('test-day-1', DATE '2030-01-01', 'incremental'),
    ('test-day-5', DATE '2030-01-05', 'incremental'),
    ('test-day-9', DATE '2030-01-09', 'incremental');

TRUNCATE stg_asset, stg_cve;

-- day 1: a new asset and a new CVE
INSERT INTO stg_asset (asset_id, hostname, ip_address, os_name, software_name, software_version, asset_type, department_name,
                       asset_owner, criticality_level, asset_criticality_score, exposure_level, internet_exposed_flag,
                       environment, location_name, asset_status, active_flag, source_row_no, batch_id)
VALUES ('AST-TEST-01', 'test-01', '10.0.0.1', 'Debian', 'Redis', '6.0.0', 'Database', 'Finance', 'fin-ops@corp.com',
        'Low', 1, 'Internal', FALSE, 'Production', 'Lahore', 'Active', TRUE, 1, 'test-day-1');
INSERT INTO stg_cve (cve_id, source_identifier, vulnerability_status, description_en, published_at, last_modified_at, batch_id)
VALUES ('CVE-2099-0001', 'test', 'Received', 'first text', TIMESTAMP '2030-01-01 10:00', TIMESTAMP '2030-01-01 10:00', 'test-day-1');

\set batch_id test-day-1
\set batch_date 2030-01-01
\ir ../etl/42_load_dim_asset.sql
\ir ../etl/43_load_dim_cve.sql

DO $$ BEGIN
    PERFORM pg_temp.check('scd2', 'day 1: new asset gets one current row',
       (SELECT count(*) FROM dim_asset WHERE asset_id = 'AST-TEST-01' AND is_current), 1::BIGINT);
    PERFORM pg_temp.check('scd2', 'day 1: new asset gets a surrogate key >= 1001',
       (SELECT asset_key >= 1001 FROM dim_asset WHERE asset_id = 'AST-TEST-01'), TRUE);
END $$;
CREATE TEMP TABLE day1 ON COMMIT DROP AS
SELECT (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-TEST-01') AS asset_key,
       (SELECT cve_key FROM dim_cve WHERE cve_id = 'CVE-2099-0001') AS cve_key;

-- day 5: criticality and exposure change (Type 2), CVE only gets a new lastModified (Type 1)
UPDATE stg_asset SET criticality_level = 'Critical', asset_criticality_score = 4,
                     exposure_level = 'Internet-facing', internet_exposed_flag = TRUE, batch_id = 'test-day-5';
UPDATE stg_cve SET last_modified_at = TIMESTAMP '2030-01-05 09:00', batch_id = 'test-day-5';

\set batch_id test-day-5
\set batch_date 2030-01-05
\ir ../etl/42_load_dim_asset.sql
\ir ../etl/43_load_dim_cve.sql

DO $$ BEGIN
    PERFORM pg_temp.check('scd2', 'day 5: changed asset now has two versions',
       (SELECT count(*) FROM dim_asset WHERE asset_id = 'AST-TEST-01'), 2::BIGINT);
    PERFORM pg_temp.check('scd2', 'day 5: old version closed the day before the change',
       (SELECT effective_end_date FROM dim_asset WHERE asset_key = (SELECT asset_key FROM day1)), DATE '2030-01-04');
    PERFORM pg_temp.check('scd2', 'day 5: old version is no longer current',
       (SELECT is_current FROM dim_asset WHERE asset_key = (SELECT asset_key FROM day1)), FALSE);
    PERFORM pg_temp.check('scd2', 'day 5: old version keeps its old criticality (history preserved)',
       (SELECT criticality_level FROM dim_asset WHERE asset_key = (SELECT asset_key FROM day1))::TEXT, 'Low');
    PERFORM pg_temp.check('scd2', 'day 5: new current version has the new criticality and a new surrogate key',
       (SELECT criticality_level || '|' || (asset_key <> (SELECT asset_key FROM day1))
        FROM dim_asset WHERE asset_id = 'AST-TEST-01' AND is_current)::TEXT, 'Critical|true');
    PERFORM pg_temp.check('scd2', 'day 5: new version starts on the batch date',
       (SELECT effective_start_date FROM dim_asset WHERE asset_id = 'AST-TEST-01' AND is_current), DATE '2030-01-05');
    PERFORM pg_temp.check('scd2', 'day 5: CVE lastModified-only change does not create a version (Type 1)',
       (SELECT count(*) FROM dim_cve WHERE cve_id = 'CVE-2099-0001'), 1::BIGINT);
    PERFORM pg_temp.check('scd2', 'day 5: CVE keeps its surrogate key and gets the new lastModified',
       (SELECT (cve_key = (SELECT cve_key FROM day1)) AND last_modified_date_key = 20300105
        FROM dim_cve WHERE cve_id = 'CVE-2099-0001'), TRUE);
END $$;

-- day 5 again: a second change on the same day overwrites today's version
UPDATE stg_asset SET department_name = 'Security';
UPDATE stg_cve SET vulnerability_status = 'Analyzed';
\ir ../etl/42_load_dim_asset.sql
\ir ../etl/43_load_dim_cve.sql

DO $$ BEGIN
    PERFORM pg_temp.check('scd2', 'same-day change updates today''s version in place',
       (SELECT count(*) || '|' || max(department_name) FILTER (WHERE is_current)
        FROM dim_asset WHERE asset_id = 'AST-TEST-01')::TEXT, '2|Security');
    PERFORM pg_temp.check('scd2', 'CVE status change creates a second CVE version',
       (SELECT count(*) || '|' || max(vulnerability_status) FILTER (WHERE is_current)
        FROM dim_cve WHERE cve_id = 'CVE-2099-0001')::TEXT, '2|Analyzed');
END $$;

-- day 9: same data again -> nothing changes
\set batch_id test-day-9
\set batch_date 2030-01-09
\ir ../etl/42_load_dim_asset.sql
\ir ../etl/43_load_dim_cve.sql

DO $$ BEGIN
    PERFORM pg_temp.check('scd2', 'unchanged reload creates no new versions',
       (SELECT count(*) FROM dim_asset WHERE asset_id = 'AST-TEST-01')
     + (SELECT count(*) FROM dim_cve WHERE cve_id = 'CVE-2099-0001'), 4::BIGINT);
    PERFORM pg_temp.check('scd2', 'exactly one current row per natural key after all loads',
       (SELECT count(*) FROM dim_asset WHERE asset_id = 'AST-TEST-01' AND is_current)
     + (SELECT count(*) FROM dim_cve WHERE cve_id = 'CVE-2099-0001' AND is_current), 2::BIGINT);
END $$;


-- 4. Business key -> surrogate key lookup as used by the fact loads

DO $$ BEGIN
    PERFORM pg_temp.check('fact keys', 'asset_id resolves to the current surrogate key only',
       (SELECT count(*) FROM stg_asset s JOIN dim_asset a ON a.asset_id = s.asset_id AND a.is_current), 1::BIGINT);
    PERFORM pg_temp.check('fact keys', 'current surrogate key is the day-5 version',
       (SELECT a.effective_start_date FROM stg_asset s JOIN dim_asset a ON a.asset_id = s.asset_id AND a.is_current),
       DATE '2030-01-05');
END $$;


-- Restore sequences, report, fail on any failed test

DO $$ BEGIN
    PERFORM CASE WHEN last_value IS NULL THEN setval(seq, start_value, FALSE) ELSE setval(seq, last_value, TRUE) END
    FROM saved_sequence;
END $$;

\pset footer off
SELECT test_group, count(*) AS tests, count(*) FILTER (WHERE passed) AS passed, count(*) FILTER (WHERE NOT passed) AS failed
FROM test_result GROUP BY test_group ORDER BY min(test_no);

SELECT test_no, test_group, test_name, detail FROM test_result WHERE NOT passed ORDER BY test_no;

SET client_min_messages = notice;
DO $$
DECLARE v_failed INT; v_total INT;
BEGIN
    SELECT count(*) FILTER (WHERE NOT passed), count(*) INTO v_failed, v_total FROM test_result;
    IF v_failed > 0 THEN
        RAISE EXCEPTION '% of % ETL tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % ETL tests passed', v_total;
END $$;

ROLLBACK;
