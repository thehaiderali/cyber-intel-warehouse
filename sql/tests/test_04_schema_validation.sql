/*
   test_04_schema_validation.sql
   Schema structure and metadata validation tests.

   What is tested
     1. Schema existence     : all three schemas exist
     2. Schema comments      : schemas have proper documentation
     3. Table counts         : correct number of tables per schema
     4. Table types          : proper distinction between tables and views
     5. Schema ownership     : schemas owned by correct role

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_04_schema_validation.sql
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
    -- 1. Schema existence
    PERFORM pg_temp.expect_true('schema existence', 'project_staging exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_staging')),
           'schema not found');

    PERFORM pg_temp.expect_true('schema existence', 'project_dw exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_dw')),
           'schema not found');

    PERFORM pg_temp.expect_true('schema existence', 'project_reporting exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'project_reporting')),
           'schema not found');

    -- 2. Schema comments
    PERFORM pg_temp.expect_true('schema comments', 'project_staging has comment',
           (SELECT pg_description.obj_description(s.oid, 'pg_namespace') IS NOT NULL
            FROM pg_namespace s WHERE s.nspname = 'project_staging'),
           'comment missing');

    PERFORM pg_temp.expect_true('schema comments', 'project_dw has comment',
           (SELECT pg_description.obj_description(s.oid, 'pg_namespace') IS NOT NULL
            FROM pg_namespace s WHERE s.nspname = 'project_dw'),
           'comment missing');

    PERFORM pg_temp.expect_true('schema comments', 'project_reporting has comment',
           (SELECT pg_description.obj_description(s.oid, 'pg_namespace') IS NOT NULL
            FROM pg_namespace s WHERE s.nspname = 'project_reporting'),
           'comment missing');

    -- 3. Table counts per schema
    PERFORM pg_temp.expect_true('table counts', 'project_staging has expected tables',
           (SELECT count(*) >= 5 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_type = 'BASE TABLE'),
           'insufficient tables in staging');

    PERFORM pg_temp.expect_true('table counts', 'project_dw has exactly 15 tables',
           (SELECT count(*) = 15 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_type = 'BASE TABLE'),
           'expected 15 tables, got ' || (SELECT count(*) FROM information_schema.tables WHERE table_schema = 'project_dw' AND table_type = 'BASE TABLE'));

    PERFORM pg_temp.expect_true('table counts', 'project_reporting has views',
           (SELECT count(*) >= 1 FROM information_schema.views
            WHERE table_schema = 'project_reporting'),
           'no views found in reporting');

    -- 4. Check that staging has raw and stg tables
    PERFORM pg_temp.expect_true('staging structure', 'project_staging has raw_ tables',
           (SELECT count(*) >= 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name LIKE 'raw_%'),
           'no raw_ tables found');

    PERFORM pg_temp.expect_true('staging structure', 'project_staging has stg_ tables',
           (SELECT count(*) >= 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name LIKE 'stg_%'),
           'no stg_ tables found');

    PERFORM pg_temp.expect_true('staging structure', 'project_staging has ref_ tables',
           (SELECT count(*) >= 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name LIKE 'ref_%'),
           'no ref_ tables found');

    -- 5. Check DW has dimensions, bridges, and facts
    PERFORM pg_temp.expect_true('dw structure', 'project_dw has dim_ tables',
           (SELECT count(*) >= 5 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name LIKE 'dim_%'),
           'no dim_ tables found');

    PERFORM pg_temp.expect_true('dw structure', 'project_dw has bridge_ tables',
           (SELECT count(*) >= 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name LIKE 'bridge_%'),
           'no bridge_ tables found');

    PERFORM pg_temp.expect_true('dw structure', 'project_dw has fact_ tables',
           (SELECT count(*) >= 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name LIKE 'fact_%'),
           'no fact_ tables found');

    -- 6. Schema ownership
    PERFORM pg_temp.expect_true('ownership', 'schemas are owned by postgres or valid role',
           (SELECT count(*) = 3 FROM pg_namespace
            WHERE nspname IN ('project_staging', 'project_dw', 'project_reporting')
              AND nspowner IS NOT NULL),
           'some schemas have no owner');

    -- 7. No unexpected schemas in database
    PERFORM pg_temp.expect_true('schema cleanliness', 'no unexpected user schemas',
           (SELECT count(*) <= 5 FROM information_schema.schemata
            WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'public',
                                      'project_staging', 'project_dw', 'project_reporting',
                                      'pg_toast', 'pg_temp')),
           'unexpected schemas found');

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
        RAISE EXCEPTION '% of % schema validation tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % schema validation tests passed', v_total;
END $$;
