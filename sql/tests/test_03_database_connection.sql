/*
   test_03_database_connection.sql
   Basic database connectivity and configuration tests.

   What is tested
     1. Connection    : database exists, version requirements met
     2. Permissions   : required privileges on schemas
     3. Configuration  : search path, client encoding, timezone settings

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_03_database_connection.sql
*/

SET client_min_messages = warning;

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
    -- 1. Connection and database existence
    PERFORM pg_temp.expect_true('connection', 'database name is intel_dw',
           current_database() = 'intel_dw',
           'current database is ' || current_database());

    PERFORM pg_temp.expect_true('connection', 'PostgreSQL version is 15 or higher',
           (SELECT split_part(version(), ' ', 2)::NUMERIC >= 15),
           'version is ' || version());

    PERFORM pg_temp.expect_true('connection', 'database is accepting connections',
           (SELECT count(*) = 1 FROM pg_stat_activity WHERE datname = current_database() AND pid = pg_backend_pid()),
           'backend process not found');

    -- 2. Schema existence and access
    PERFORM pg_temp.expect_true('schema', 'project_staging schema exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_staging')),
           'schema not found');

    PERFORM pg_temp.expect_true('schema', 'project_dw schema exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_dw')),
           'schema not found');

    PERFORM pg_temp.expect_true('schema', 'project_reporting schema exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_reporting')),
           'schema not found');

    -- 3. Privileges
    PERFORM pg_temp.expect_true('privileges', 'USAGE privilege on project_staging',
           (SELECT has_schema_privilege('public', 'project_staging', 'USAGE')),
           'USAGE privilege missing');

    PERFORM pg_temp.expect_true('privileges', 'USAGE privilege on project_dw',
           (SELECT has_schema_privilege('public', 'project_dw', 'USAGE')),
           'USAGE privilege missing');

    PERFORM pg_temp.expect_true('privileges', 'USAGE privilege on project_reporting',
           (SELECT has_schema_privilege('public', 'project_reporting', 'USAGE')),
           'USAGE privilege missing');

    -- 4. Configuration
    PERFORM pg_temp.expect_true('config', 'client_encoding is UTF8',
           (SELECT pg_client_encoding() = 'UTF8'),
           'encoding is ' || pg_client_encoding());

    PERFORM pg_temp.expect_true('config', 'timezone is set',
           (SELECT current_setting('timezone') IS NOT NULL),
           'timezone not set');

    PERFORM pg_temp.expect_true('config', 'client_min_messages can be set',
           (SELECT current_setting('client_min_messages') IS NOT NULL),
           'client_min_messages not accessible');

    -- 5. Extensions (if any are required)
    PERFORM pg_temp.expect_true('extensions', 'plpgsql language is available',
           (SELECT EXISTS (SELECT 1 FROM pg_language WHERE lanname = 'plpgsql')),
           'plpgsql not available');

    -- 6. System catalogs accessible
    PERFORM pg_temp.expect_true('catalogs', 'pg_class accessible',
           (SELECT count(*) > 0 FROM pg_class LIMIT 1),
           'pg_class not accessible');

    PERFORM pg_temp.expect_true('catalogs', 'information_schema accessible',
           (SELECT count(*) > 0 FROM information_schema.tables LIMIT 1),
           'information_schema not accessible');

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
        RAISE EXCEPTION '% of % database connection tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % database connection tests passed', v_total;
END $$;
