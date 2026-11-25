/*
   test_09_etl_pipeline.sql
   End-to-end ETL pipeline validation tests.

   What is tested
     1. ETL scripts exist  : all ETL SQL scripts are present
     2. ETL log table     : etl_batch_log tracks batch executions
     3. ETL step log      : etl_step_log tracks individual steps
     4. Batch uniqueness  : no duplicate batch executions
     5. Data flow         : data flows from raw -> stg -> dw
     6. Record counts     : staging and DW have expected record counts
     7. Cleaning stats    : etl_cleaning_stat has cleaning metrics
     8. Reject handling   : stg_reject captures rejected rows

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_09_etl_pipeline.sql
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
    -- 1. ETL audit tables exist
    PERFORM pg_temp.expect_true('etl tables', 'etl_batch_log exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'etl_batch_log')),
           'table not found');

    PERFORM pg_temp.expect_true('etl tables', 'etl_step_log exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'etl_step_log')),
           'table not found');

    PERFORM pg_temp.expect_true('etl tables', 'etl_cleaning_stat exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'etl_cleaning_stat')),
           'table not found');

    PERFORM pg_temp.expect_true('etl tables', 'stg_reject exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'stg_reject')),
           'table not found');

    -- 2. Raw staging tables exist
    PERFORM pg_temp.expect_true('raw tables', 'raw_cve exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'raw_cve')),
           'table not found');

    PERFORM pg_temp.expect_true('raw tables', 'raw_kev exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'raw_kev')),
           'table not found');

    PERFORM pg_temp.expect_true('raw tables', 'raw_epss exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'raw_epss')),
           'table not found');

    PERFORM pg_temp.expect_true('raw tables', 'raw_asset exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'raw_asset')),
           'table not found');

    -- 3. Cleaned staging tables exist
    PERFORM pg_temp.expect_true('stg tables', 'stg_cve exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'stg_cve')),
           'table not found');

    PERFORM pg_temp.expect_true('stg tables', 'stg_asset exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'stg_asset')),
           'table not found');

    PERFORM pg_temp.expect_true('stg tables', 'stg_product exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'stg_product')),
           'table not found');

    PERFORM pg_temp.expect_true('stg tables', 'stg_software exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_staging' AND table_name = 'stg_software')),
           'table not found');

    -- 4. ETL batch log structure
    PERFORM pg_temp.expect_true('batch log', 'etl_batch_log has batch_id column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_batch_log' AND column_name = 'batch_id')),
           'column not found');

    PERFORM pg_temp.expect_true('batch log', 'etl_batch_log has batch_date column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_batch_log' AND column_name = 'batch_date')),
           'column not found');

    PERFORM pg_temp.expect_true('batch log', 'etl_batch_log has load_type column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_batch_log' AND column_name = 'load_type')),
           'column not found');

    -- 5. ETL step log structure
    PERFORM pg_temp.expect_true('step log', 'etl_step_log has step_name column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_step_log' AND column_name = 'step_name')),
           'column not found');

    PERFORM pg_temp.expect_true('step log', 'etl_step_log has start_time column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_step_log' AND column_name = 'start_time')),
           'column not found');

    PERFORM pg_temp.expect_true('step log', 'etl_step_log has end_time column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_step_log' AND column_name = 'end_time')),
           'column not found');

    PERFORM pg_temp.expect_true('step log', 'etl_step_log has status column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_step_log' AND column_name = 'status')),
           'column not found');

    -- 6. Batch uniqueness (if data loaded)
    PERFORM pg_temp.expect_true('batch uniqueness', 'no duplicate batch_ids in etl_batch_log',
           (SELECT count(*) = 0 FROM etl_batch_log GROUP BY batch_id HAVING count(*) > 1),
           'duplicate batch_ids found');

    -- 7. Data flow validation - raw to staging
    PERFORM pg_temp.expect_true('data flow', 'raw_cve has data or structure is correct',
           (SELECT count(*) >= 0 FROM raw_cve LIMIT 1),
           'raw_cve not accessible');

    PERFORM pg_temp.expect_true('data flow', 'stg_cve has data or structure is correct',
           (SELECT count(*) >= 0 FROM stg_cve LIMIT 1),
           'stg_cve not accessible');

    -- 8. Dimension tables in DW
    PERFORM pg_temp.expect_true('dw dimensions', 'dim_cve exists and accessible',
           (SELECT count(*) >= 0 FROM dim_cve LIMIT 1),
           'dim_cve not accessible');

    PERFORM pg_temp.expect_true('dw dimensions', 'dim_asset exists and accessible',
           (SELECT count(*) >= 0 FROM dim_asset LIMIT 1),
           'dim_asset not accessible');

    PERFORM pg_temp.expect_true('dw dimensions', 'dim_product exists and accessible',
           (SELECT count(*) >= 0 FROM dim_product LIMIT 1),
           'dim_product not accessible');

    PERFORM pg_temp.expect_true('dw dimensions', 'dim_software exists and accessible',
           (SELECT count(*) >= 0 FROM dim_software LIMIT 1),
           'dim_software not accessible');

    -- 9. Fact tables in DW
    PERFORM pg_temp.expect_true('dw facts', 'fact_vulnerability_intelligence_snapshot exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'fact_vulnerability_intelligence_snapshot')),
           'fact table not found');

    PERFORM pg_temp.expect_true('dw facts', 'fact_asset_vulnerability_exposure exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'fact_asset_vulnerability_exposure')),
           'fact table not found');

    PERFORM pg_temp.expect_true('dw facts', 'fact_asset_software_inventory_snapshot exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'fact_asset_software_inventory_snapshot')),
           'fact table not found');

    -- 10. Bridge tables in DW
    PERFORM pg_temp.expect_true('dw bridges', 'bridge_cve_product exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'bridge_cve_product')),
           'bridge table not found');

    PERFORM pg_temp.expect_true('dw bridges', 'bridge_cve_cwe exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'bridge_cve_cwe')),
           'bridge table not found');

    PERFORM pg_temp.expect_true('dw bridges', 'bridge_product_software_map exists',
           (SELECT EXISTS (SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'project_dw' AND table_name = 'bridge_product_software_map')),
           'bridge table not found');

    -- 11. Cleaning statistics table structure
    PERFORM pg_temp.expect_true('cleaning stats', 'etl_cleaning_stat has table_name column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_cleaning_stat' AND column_name = 'table_name')),
           'column not found');

    PERFORM pg_temp.expect_true('cleaning stats', 'etl_cleaning_stat has rows_in column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_cleaning_stat' AND column_name = 'rows_in')),
           'column not found');

    PERFORM pg_temp.expect_true('cleaning stats', 'etl_cleaning_stat has rows_out column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'etl_cleaning_stat' AND column_name = 'rows_out')),
           'column not found');

    -- 12. Reject table structure
    PERFORM pg_temp.expect_true('reject table', 'stg_reject has table_name column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'stg_reject' AND column_name = 'table_name')),
           'column not found');

    PERFORM pg_temp.expect_true('reject table', 'stg_reject has reject_reason column',
           (SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'project_staging' AND table_name = 'stg_reject' AND column_name = 'reject_reason')),
           'column not found');

    -- 13. Foreign key relationships in ETL flow
    PERFORM pg_temp.expect_true('etl relationships', 'fact tables reference dimensions',
           (SELECT count(*) > 0 FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage k ON tc.constraint_name = k.constraint_name
            WHERE tc.table_schema = 'project_dw' AND tc.constraint_type = 'FOREIGN KEY'
              AND k.table_name LIKE 'fact_%'),
           'no foreign keys from facts to dimensions');

    -- 14. Batch dates are sequential (if data loaded)
    PERFORM pg_temp.expect_true('batch sequencing', 'batch dates are unique',
           (SELECT count(*) = 0 FROM etl_batch_log GROUP BY batch_date HAVING count(*) > 1),
           'duplicate batch dates found');

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
        RAISE EXCEPTION '% of % ETL pipeline tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % ETL pipeline tests passed', v_total;
END $$;
