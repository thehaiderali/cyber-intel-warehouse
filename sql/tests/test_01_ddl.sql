/*
   test_01_ddl.sql
   Automated tests for the database structure built by 01-03.

   What is tested
     1. Structure : every Phase 1 ERD table and column exists in the right schema,
                    every table has a primary key, every *_key column in a
                    fact/bridge has a foreign key.
     2. Behaviour : constraints accept valid rows and reject invalid ones
                    (business rules BR-02 .. BR-06, grain uniqueness, SCD2,
                    surrogate key start values, referential integrity).

   Everything runs inside one transaction that is rolled back, so the
   warehouse is left untouched. The script ends with an error (non-zero exit
   code under ON_ERROR_STOP) if any test fails.

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/tests/test_01_ddl.sql
*/

SET client_min_messages = warning;
BEGIN;

-- Identity sequences are not rolled back by ROLLBACK, so remember their state
-- and restore it at the end; otherwise every test run would shift real keys
-- (the first real asset would get 1002 instead of 1001).
CREATE TEMP TABLE saved_sequence ON COMMIT DROP AS
SELECT format('%I.%I', schemaname, sequencename) AS seq, start_value, last_value
FROM pg_sequences
WHERE schemaname IN ('project_staging', 'project_dw');

CREATE TEMP TABLE test_result (
    test_no     INT GENERATED ALWAYS AS IDENTITY,
    test_group  TEXT,
    test_name   TEXT,
    passed      BOOLEAN,
    detail      TEXT
) ON COMMIT DROP;

-- Runs a statement that must succeed.
CREATE FUNCTION pg_temp.expect_ok(p_group TEXT, p_name TEXT, p_sql TEXT) RETURNS VOID AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
        INSERT INTO test_result (test_group, test_name, passed) VALUES (p_group, p_name, TRUE);
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO test_result (test_group, test_name, passed, detail) VALUES (p_group, p_name, FALSE, SQLSTATE || ' ' || SQLERRM);
    END;
END $$ LANGUAGE plpgsql;

-- Runs a statement that must be rejected with the given SQLSTATE class:
--   23502 not_null, 23503 foreign_key, 23505 unique, 23514 check.
-- The statement runs in its own subtransaction, so its effect is undone either way.
CREATE FUNCTION pg_temp.expect_fail(p_group TEXT, p_name TEXT, p_sql TEXT, p_sqlstate TEXT) RETURNS VOID AS $$
DECLARE
    v_ok BOOLEAN := FALSE;
BEGIN
    BEGIN
        EXECUTE p_sql;
        v_ok := TRUE;
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'statement was accepted';
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO test_result (test_group, test_name, passed, detail)
        VALUES (p_group, p_name,
                NOT v_ok AND SQLSTATE = p_sqlstate,
                CASE WHEN v_ok THEN 'expected ' || p_sqlstate || ' but the statement was accepted'
                     WHEN SQLSTATE <> p_sqlstate THEN 'expected ' || p_sqlstate || ' got ' || SQLSTATE || ' ' || SQLERRM
                END);
    END;
END $$ LANGUAGE plpgsql;

-- Checks a boolean condition. Set-based checks insert into test_result directly.
CREATE FUNCTION pg_temp.expect_true(p_group TEXT, p_name TEXT, p_condition BOOLEAN, p_detail TEXT DEFAULT NULL) RETURNS VOID AS $$
    INSERT INTO test_result (test_group, test_name, passed, detail)
    VALUES (p_group, p_name, coalesce(p_condition, FALSE), CASE WHEN NOT coalesce(p_condition, FALSE) THEN p_detail END);
$$ LANGUAGE sql;


-- All checks run in one PL/pgSQL block (PERFORM keeps the output quiet).
SET LOCAL search_path = project_dw, project_staging;

DO $tests$
BEGIN

    -- 1. Structure

    -- Every table and column of the Phase 1 ERD must exist in project_dw.
    CREATE TEMP TABLE expected_column (table_name TEXT, column_name TEXT) ON COMMIT DROP;
    INSERT INTO expected_column
    SELECT t, unnest(cols) FROM (VALUES
      ('dim_date', ARRAY['date_key','full_date','day_number','day_name','week_number','month_number','month_name','quarter_number','year_number','is_weekend']),
      ('dim_cve', ARRAY['cve_key','cve_id','source_identifier','vulnerability_status','description_en','primary_cwe_code','published_date_key','last_modified_date_key','record_source','effective_start_date','effective_end_date','is_current']),
      ('dim_product', ARRAY['product_key','vendor_name','product_name','vendor_product_name','source_vendor_name','source_product_name','normalization_status']),
      ('dim_software', ARRAY['software_key','software_name','software_vendor','software_version','normalized_software_name','normalized_vendor_name','normalization_status']),
      ('dim_asset', ARRAY['asset_key','asset_id','hostname','ip_address','asset_type','environment','criticality_level','internet_exposed_flag','active_flag','asset_owner','department_name','location_name','effective_start_date','effective_end_date','is_current']),
      ('dim_cvss', ARRAY['cvss_key','cvss_version','base_score','base_severity','attack_vector','attack_complexity','privileges_required','user_interaction','scope','confidentiality_impact','integrity_impact','availability_impact','vector_string']),
      ('dim_cwe', ARRAY['cwe_key','cwe_code','cwe_description']),
      ('dim_kev_status', ARRAY['kev_status_key','is_kev_listed','known_ransomware_use','forensic_triage_required','required_action']),
      ('dim_risk_band', ARRAY['risk_band_key','risk_band_name','minimum_score','maximum_score','priority_rank']),
      ('bridge_cve_product', ARRAY['cve_key','product_key','version_start_including','version_start_excluding','version_end_including','version_end_excluding','default_status','match_source']),
      ('bridge_cve_cwe', ARRAY['cve_key','cwe_key']),
      ('bridge_product_software_map', ARRAY['product_software_map_key','product_key','software_key','match_method','match_confidence','mapping_notes','is_active']),
      ('fact_vulnerability_intelligence_snapshot', ARRAY['vulnerability_snapshot_key','assessment_date_key','published_date_key','last_modified_date_key','kev_date_added_key','kev_due_date_key','cve_key','cvss_key','kev_status_key','risk_band_key','epss_score','epss_percentile','cvss_base_score','kev_listed_flag','ransomware_use_flag','forensic_triage_flag','days_to_kev_due_date','vulnerability_risk_score']),
      ('fact_asset_software_inventory_snapshot', ARRAY['asset_inventory_snapshot_key','snapshot_date_key','asset_key','software_key','installed_software_count','active_asset_flag','internet_exposed_flag','asset_criticality_score']),
      ('fact_asset_vulnerability_exposure', ARRAY['asset_vulnerability_exposure_key','assessment_date_key','remediation_due_date_key','cve_key','asset_key','software_key','product_key','cvss_key','kev_status_key','risk_band_key','match_confidence','version_match_flag','asset_criticality_score','internet_exposed_flag','epss_score','cvss_base_score','kev_listed_flag','risk_priority_score','remediation_status','days_open'])
    ) AS v(t, cols);

    INSERT INTO test_result (test_group, test_name, passed, detail)
    SELECT 'structure', 'ERD column ' || e.table_name || '.' || e.column_name, c.column_name IS NOT NULL,
           CASE WHEN c.column_name IS NULL THEN 'column missing' END
    FROM expected_column e
    LEFT JOIN information_schema.columns c
           ON c.table_schema = 'project_dw' AND c.table_name = e.table_name AND c.column_name = e.column_name;

    PERFORM pg_temp.expect_true('structure', 'three layer schemas exist',
           (SELECT count(*) FROM information_schema.schemata
            WHERE schema_name IN ('project_staging', 'project_dw', 'project_reporting')) = 3);

    PERFORM pg_temp.expect_true('structure', 'project_dw has exactly 15 tables (9 dims, 3 bridges, 3 facts)',
           (SELECT count(*) FROM information_schema.tables WHERE table_schema = 'project_dw' AND table_type = 'BASE TABLE') = 15);

    INSERT INTO test_result (test_group, test_name, passed)
    SELECT 'structure', 'primary key on ' || t.table_schema || '.' || t.table_name,
           EXISTS (SELECT 1 FROM information_schema.table_constraints tc
                   WHERE tc.table_schema = t.table_schema AND tc.table_name = t.table_name AND tc.constraint_type = 'PRIMARY KEY')
    FROM information_schema.tables t
    WHERE t.table_schema IN ('project_staging', 'project_dw') AND t.table_type = 'BASE TABLE';


    -- Every surrogate-key column in a fact or bridge (other than its own PK) must be a foreign key.
    INSERT INTO test_result (test_group, test_name, passed)
    SELECT 'structure', 'foreign key on ' || c.table_name || '.' || c.column_name,
           EXISTS (SELECT 1
                   FROM information_schema.key_column_usage k
                   JOIN information_schema.table_constraints tc
                     ON tc.constraint_name = k.constraint_name AND tc.table_schema = k.table_schema
                   WHERE tc.constraint_type = 'FOREIGN KEY' AND k.table_schema = 'project_dw'
                     AND k.table_name = c.table_name AND k.column_name = c.column_name)
    FROM information_schema.columns c
    WHERE c.table_schema = 'project_dw'
      AND (c.table_name LIKE 'fact\_%' OR c.table_name LIKE 'bridge\_%')
      AND c.column_name LIKE '%\_key'
      AND c.column_name NOT IN ('vulnerability_snapshot_key', 'asset_inventory_snapshot_key',
                                'asset_vulnerability_exposure_key', 'product_software_map_key', 'cve_product_key');


    -- 2. Behaviour - test fixtures (one valid row per dimension)


    INSERT INTO dim_date (date_key, full_date, day_number, day_name, week_number, month_number, month_name, quarter_number, year_number, is_weekend)
    VALUES (-1, NULL, NULL, 'Unknown', NULL, NULL, 'Unknown', NULL, NULL, NULL),
           (20261010, DATE '2026-10-10', 10, 'Saturday', 41, 10, 'October', 4, 2026, TRUE);

    INSERT INTO dim_cve (cve_key, cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date)
    VALUES (-1, 'Unknown', -1, -1, md5(''), DATE '1900-01-01');
    INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date)
    VALUES ('CVE-2021-41773', 20261010, 20261010, md5('v1'), DATE '2026-10-10');

    INSERT INTO dim_product (vendor_name, product_name, vendor_product_name, normalization_status)
    VALUES ('apache', 'http_server', 'apache:http_server', 'CPE');
    INSERT INTO dim_software (software_name, software_version, normalized_software_name, normalization_status)
    VALUES ('Apache HTTP Server', '2.4.49', 'apache http server', 'Mapped');
    INSERT INTO dim_cvss (cvss_version, base_score, base_severity, vector_string)
    VALUES ('3.1', 7.5, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
    INSERT INTO dim_kev_status (is_kev_listed, known_ransomware_use, forensic_triage_required, required_action)
    VALUES (TRUE, 'Known', FALSE, 'Apply updates per vendor instructions.');
    INSERT INTO dim_risk_band (risk_band_name, minimum_score, maximum_score, priority_rank, remediation_sla_days)
    VALUES ('Critical', 70, 100, 1, 15);
    INSERT INTO dim_cwe (cwe_code, cwe_description) VALUES ('CWE-22', 'Path Traversal');

    CREATE TEMP TABLE k ON COMMIT DROP AS
    SELECT (SELECT cve_key FROM dim_cve WHERE cve_id = 'CVE-2021-41773')  AS cve,
           (SELECT product_key FROM dim_product)                          AS product,
           (SELECT software_key FROM dim_software)                        AS software,
           (SELECT cvss_key FROM dim_cvss)                                AS cvss,
           (SELECT kev_status_key FROM dim_kev_status)                    AS kev,
           (SELECT risk_band_key FROM dim_risk_band)                      AS band,
           (SELECT cwe_key FROM dim_cwe)                                  AS cwe;

    -- Surrogate keys
    PERFORM pg_temp.expect_ok('surrogate key', 'dim_asset accepts a new asset',
           $q$INSERT INTO dim_asset (asset_id, criticality_level, asset_criticality_score, internet_exposed_flag, active_flag, row_hash, effective_start_date)
              VALUES ('AST-APACHE-01', 'Medium', 2, TRUE, TRUE, md5('a1'), DATE '2026-10-10')$q$);
    PERFORM pg_temp.expect_true('surrogate key', 'dim_asset surrogate key sequence starts at 1001',
           (SELECT seqstart FROM pg_sequence WHERE seqrelid = pg_get_serial_sequence('project_dw.dim_asset', 'asset_key')::regclass) = 1001);
    PERFORM pg_temp.expect_true('surrogate key', 'generated dim_asset key is >= 1001',
           (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01') >= 1001,
           'got ' || (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'));
    PERFORM pg_temp.expect_true('surrogate key', 'surrogate key differs from business key and both are stored',
           (SELECT asset_key::text <> asset_id FROM dim_asset WHERE asset_id = 'AST-APACHE-01'));
    PERFORM pg_temp.expect_true('surrogate key', 'unknown member -1 coexists with generated keys',
           (SELECT count(*) FROM dim_cve WHERE cve_key = -1) = 1 AND (SELECT min(cve_key) FROM dim_cve WHERE cve_key > 0) >= 1);
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_product natural key vendor:product is unique',
           $q$INSERT INTO dim_product (vendor_name, product_name, vendor_product_name, normalization_status)
              VALUES ('apache', 'http_server', 'apache:http_server', 'CPE')$q$, '23505');
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_cwe natural key cwe_code is unique',
           $q$INSERT INTO dim_cwe (cwe_code) VALUES ('CWE-22')$q$, '23505');
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_software natural key (name, version) is unique',
           $q$INSERT INTO dim_software (software_name, software_version, normalized_software_name, normalization_status)
              VALUES ('APACHE HTTP SERVER', '2.4.49', 'apache http server', 'Mapped')$q$, '23505');
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_cvss rejects duplicate version+vector+score',
           $q$INSERT INTO dim_cvss (cvss_version, base_score, base_severity, vector_string)
              VALUES ('3.1', 7.5, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')$q$, '23505');
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_cvss treats NULL vectors as equal (single "no CVSS" member)',
           $q$INSERT INTO dim_cvss (cvss_version, base_score, vector_string) VALUES (NULL, NULL, NULL), (NULL, NULL, NULL)$q$, '23505');
    PERFORM pg_temp.expect_fail('surrogate key', 'dim_kev_status rejects duplicate flag combination',
           $q$INSERT INTO dim_kev_status (is_kev_listed, known_ransomware_use, forensic_triage_required, required_action)
              VALUES (TRUE, 'Known', FALSE, 'Apply updates per vendor instructions.')$q$, '23505');

    -- SCD Type 2
    PERFORM pg_temp.expect_fail('scd2', 'dim_cve allows only one current row per cve_id',
           $q$INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date)
              VALUES ('CVE-2021-41773', 20261010, 20261010, md5('v2'), DATE '2026-10-11')$q$, '23505');
    PERFORM pg_temp.expect_ok('scd2', 'dim_cve accepts a new version after expiring the old one',
           $q$UPDATE dim_cve SET is_current = FALSE, effective_end_date = DATE '2026-10-10' WHERE cve_id = 'CVE-2021-41773';
              INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date)
              VALUES ('CVE-2021-41773', 20261010, 20261010, md5('v2'), DATE '2026-10-11')$q$);
    PERFORM pg_temp.expect_true('scd2', 'two versions of the CVE, exactly one current',
           (SELECT count(*) = 2 AND count(*) FILTER (WHERE is_current) = 1 FROM dim_cve WHERE cve_id = 'CVE-2021-41773'));
    PERFORM pg_temp.expect_fail('scd2', 'dim_cve rejects two versions starting the same day',
           $q$INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date, is_current)
              VALUES ('CVE-2021-41773', 20261010, 20261010, md5('v3'), DATE '2026-10-11', FALSE)$q$, '23505');
    PERFORM pg_temp.expect_fail('scd2', 'dim_cve rejects end date before start date',
           $q$INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date, effective_end_date)
              VALUES ('CVE-2000-0001', 20261010, 20261010, md5('x'), DATE '2026-10-10', DATE '2026-10-01')$q$, '23514');
    PERFORM pg_temp.expect_fail('scd2', 'dim_asset allows only one current row per asset_id',
           $q$INSERT INTO dim_asset (asset_id, row_hash, effective_start_date) VALUES ('AST-APACHE-01', md5('a2'), DATE '2026-10-12')$q$, '23505');
    PERFORM pg_temp.expect_fail('scd2', 'dim_cve rejects a published date missing from dim_date',
           $q$INSERT INTO dim_cve (cve_id, published_date_key, last_modified_date_key, row_hash, effective_start_date)
              VALUES ('CVE-2000-0002', 19990101, 20261010, md5('x'), DATE '2026-10-10')$q$, '23503');

    -- Referential integrity and grain of the facts
    PERFORM pg_temp.expect_ok('fact', 'valid vulnerability snapshot row loads',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, epss_score, epss_percentile, cvss_base_score,
               kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (20261010, 20261010, 20261010, -1, -1, %s, %s, %s, %s, 0.94, 0.99, 7.5, 1, 1, 0, 88.6, 'test')$q$,
              (SELECT cve FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)));
    PERFORM pg_temp.expect_fail('fact', 'snapshot grain: one row per CVE per date',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (20261010, 20261010, 20261010, -1, -1, %s, %s, %s, %s, 0, 0, 0, 10, 'test')$q$,
              (SELECT cve FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23505');
    PERFORM pg_temp.expect_fail('fact', 'snapshot rejects an orphan cve_key',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (20261010, 20261010, 20261010, -1, -1, 999999, %s, %s, %s, 0, 0, 0, 10, 'test')$q$,
              (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23503');
    PERFORM pg_temp.expect_fail('fact', 'snapshot rejects NULL dimension key (unknown member -1 must be used)',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (20261010, 20261010, 20261010, NULL, -1, %s, %s, %s, %s, 0, 0, 0, 10, 'test')$q$,
              (SELECT cve FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23502');
    PERFORM pg_temp.expect_fail('fact', 'snapshot rejects a flag that is not 0/1',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (-1, 20261010, 20261010, -1, -1, %s, %s, %s, %s, 2, 0, 0, 10, 'test')$q$,
              (SELECT cve FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23514');
    PERFORM pg_temp.expect_fail('fact', 'snapshot rejects risk score above 100',
           format($q$INSERT INTO fact_vulnerability_intelligence_snapshot
              (assessment_date_key, published_date_key, last_modified_date_key, kev_date_added_key, kev_due_date_key,
               cve_key, cvss_key, kev_status_key, risk_band_key, kev_listed_flag, ransomware_use_flag, forensic_triage_flag, vulnerability_risk_score, batch_id)
              VALUES (-1, 20261010, 20261010, -1, -1, %s, %s, %s, %s, 0, 0, 0, 100.5, 'test')$q$,
              (SELECT cve FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23514');

    PERFORM pg_temp.expect_ok('fact', 'valid inventory snapshot row loads',
           format($q$INSERT INTO fact_asset_software_inventory_snapshot
              (snapshot_date_key, asset_key, software_key, active_asset_flag, internet_exposed_flag, asset_criticality_score, batch_id)
              VALUES (20261010, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, 1, 1, 2, 'test')$q$, (SELECT software FROM k)));
    PERFORM pg_temp.expect_fail('fact', 'inventory grain: one row per asset/software/date',
           format($q$INSERT INTO fact_asset_software_inventory_snapshot
              (snapshot_date_key, asset_key, software_key, active_asset_flag, internet_exposed_flag, asset_criticality_score, batch_id)
              VALUES (20261010, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, 1, 1, 2, 'test')$q$, (SELECT software FROM k)), '23505');
    PERFORM pg_temp.expect_fail('fact', 'inventory rejects criticality score outside 1..4',
           format($q$INSERT INTO fact_asset_software_inventory_snapshot
              (snapshot_date_key, asset_key, software_key, active_asset_flag, internet_exposed_flag, asset_criticality_score, batch_id)
              VALUES (-1, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, 1, 1, 5, 'test')$q$, (SELECT software FROM k)), '23514');

    PERFORM pg_temp.expect_ok('fact', 'valid exposure row loads',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, epss_score, cvss_base_score, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (20261010, 20261010, 20261010, %s, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, %s, %s, %s, %s, 'Confirmed', 1, 2, 1, 0.94, 7.5, 1, 78.45, 'Open', 0, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)));
    PERFORM pg_temp.expect_fail('fact', 'exposure grain: one row per CVE/asset/software/date',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (20261010, 20261010, 20261010, %s, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, %s, %s, %s, %s, 'Probable', 0, 2, 1, 1, 50, 'Open', 0, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23505');
    PERFORM pg_temp.expect_fail('fact', 'exposure rejects an orphan asset_key',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (-1, 20261010, 20261010, %s, 5000, %s, %s, %s, %s, %s, 'Confirmed', 1, 2, 1, 1, 50, 'Open', 0, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23503');
    PERFORM pg_temp.expect_fail('fact', 'exposure rejects an unknown remediation status',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (-1, 20261010, 20261010, %s, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, %s, %s, %s, %s, 'Confirmed', 1, 2, 1, 1, 50, 'Pending', 0, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23514');
    PERFORM pg_temp.expect_fail('fact', 'exposure rejects an unknown match confidence',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (-1, 20261010, 20261010, %s, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, %s, %s, %s, %s, 'Maybe', 1, 2, 1, 1, 50, 'Open', 0, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23514');
    PERFORM pg_temp.expect_fail('fact', 'exposure rejects negative days_open',
           format($q$INSERT INTO fact_asset_vulnerability_exposure
              (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key, product_key,
               cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag, asset_criticality_score,
               internet_exposed_flag, kev_listed_flag, risk_priority_score, remediation_status, days_open, batch_id)
              VALUES (-1, 20261010, 20261010, %s, (SELECT asset_key FROM dim_asset WHERE asset_id = 'AST-APACHE-01'), %s, %s, %s, %s, %s, 'Confirmed', 1, 2, 1, 1, 50, 'Open', -3, 'test')$q$,
              (SELECT cve FROM k), (SELECT software FROM k), (SELECT product FROM k), (SELECT cvss FROM k), (SELECT kev FROM k), (SELECT band FROM k)), '23514');

    -- Bridges
    PERFORM pg_temp.expect_ok('bridge', 'CVE-product bridge row with a version range loads',
           format($q$INSERT INTO bridge_cve_product (cve_key, product_key, cpe_criteria, version_start_including, version_end_excluding)
              VALUES (%s, %s, 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', '2.4.0', '2.4.51')$q$, (SELECT cve FROM k), (SELECT product FROM k)));
    PERFORM pg_temp.expect_fail('bridge', 'CVE-product bridge rejects the same range twice (NULL bounds compared as equal)',
           format($q$INSERT INTO bridge_cve_product (cve_key, product_key, cpe_criteria, version_start_including, version_end_excluding)
              VALUES (%s, %s, 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', '2.4.0', '2.4.51')$q$, (SELECT cve FROM k), (SELECT product FROM k)), '23505');
    PERFORM pg_temp.expect_ok('bridge', 'CVE-product bridge accepts a second, different range',
           format($q$INSERT INTO bridge_cve_product (cve_key, product_key, cpe_criteria, version_start_including, version_end_excluding)
              VALUES (%s, %s, 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', '2.5.0', '2.5.3')$q$, (SELECT cve FROM k), (SELECT product FROM k)));
    PERFORM pg_temp.expect_fail('bridge', 'CVE-CWE bridge rejects duplicate pair',
           format($q$INSERT INTO bridge_cve_cwe VALUES (%1$s, %2$s), (%1$s, %2$s)$q$, (SELECT cve FROM k), (SELECT cwe FROM k)), '23505');
    PERFORM pg_temp.expect_fail('bridge', 'CVE-CWE bridge rejects an orphan cwe_key',
           format($q$INSERT INTO bridge_cve_cwe VALUES (%s, 999999)$q$, (SELECT cve FROM k)), '23503');
    PERFORM pg_temp.expect_fail('bridge', 'product-software map rejects duplicate pair',
           format($q$INSERT INTO bridge_product_software_map (product_key, software_key, match_method, match_confidence)
              VALUES (%1$s, %2$s, 'Manual Mapping', 'Confirmed'), (%1$s, %2$s, 'CPE', 'Probable')$q$, (SELECT product FROM k), (SELECT software FROM k)), '23505');

    -- Staging business rules
    PERFORM pg_temp.expect_ok('staging rule', 'BR-04 software version is kept as text (9.6p1, 2019 Datacenter)',
           $q$INSERT INTO stg_asset (asset_id, hostname, software_name, software_version, criticality_level, asset_criticality_score,
                                     internet_exposed_flag, active_flag, source_row_no, batch_id)
              VALUES ('T-1', 'h', 'OpenSSH', '9.6p1', 'High', 3, TRUE, TRUE, 1, 'test'),
                     ('T-2', 'h', 'Windows Server', '2019 Datacenter', 'Low', 1, FALSE, TRUE, 2, 'test')$q$);
    PERFORM pg_temp.expect_fail('staging rule', 'BR-06 criticality outside Critical/High/Medium/Low is rejected',
           $q$INSERT INTO stg_asset (asset_id, hostname, software_name, software_version, criticality_level, asset_criticality_score,
                                     internet_exposed_flag, active_flag, source_row_no, batch_id)
              VALUES ('T-3', 'h', 'x', '1', 'URGENT', 4, TRUE, TRUE, 3, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'stg_asset is unique per asset_id (duplicates collapsed)',
           $q$INSERT INTO stg_asset (asset_id, hostname, software_name, software_version, criticality_level, asset_criticality_score,
                                     internet_exposed_flag, active_flag, source_row_no, batch_id)
              VALUES ('T-1', 'h', 'x', '1', 'Low', 1, TRUE, TRUE, 4, 'test')$q$, '23505');
    PERFORM pg_temp.expect_ok('staging rule', 'BR-02 EPSS 0 and 1 are valid',
           $q$INSERT INTO stg_epss VALUES ('CVE-1999-0001', DATE '2026-10-10', 0, 1, 'v2026.06.15', 'test'),
                                          ('CVE-1999-0002', DATE '2026-10-10', 0.99999, 0.5, 'v2026.06.15', 'test')$q$);
    PERFORM pg_temp.expect_fail('staging rule', 'BR-02 EPSS above 1 is rejected',
           $q$INSERT INTO stg_epss VALUES ('CVE-1999-0003', DATE '2026-10-10', 1.2, 0.5, NULL, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'BR-02 negative EPSS percentile is rejected',
           $q$INSERT INTO stg_epss VALUES ('CVE-1999-0004', DATE '2026-10-10', 0.1, -0.5, NULL, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'EPSS is unique per CVE and score date',
           $q$INSERT INTO stg_epss VALUES ('CVE-1999-0001', DATE '2026-10-10', 0.2, 0.2, NULL, 'test')$q$, '23505');
    PERFORM pg_temp.expect_ok('staging rule', 'BR-03 CVSS 0.0 and 10.0 are valid',
           $q$INSERT INTO stg_cve (cve_id, published_at, last_modified_at, cvss_base_score, batch_id)
              VALUES ('CVE-2000-0010', now(), now(), 0.0, 'test'), ('CVE-2000-0011', now(), now(), 10.0, 'test')$q$);
    PERFORM pg_temp.expect_fail('staging rule', 'BR-03 CVSS above 10 is rejected',
           $q$INSERT INTO stg_cve (cve_id, published_at, last_modified_at, cvss_base_score, batch_id)
              VALUES ('CVE-2000-0012', now(), now(), 10.5, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'BR-01 CVE without an ID is rejected',
           $q$INSERT INTO stg_cve (cve_id, published_at, last_modified_at, batch_id) VALUES (NULL, now(), now(), 'test')$q$, '23502');
    PERFORM pg_temp.expect_ok('staging rule', 'BR-05 KEV due date on/after date added is valid',
           $q$INSERT INTO stg_kev (cve_id, date_added, due_date, known_ransomware_use, forensic_triage_required, batch_id)
              VALUES ('CVE-2021-41773', DATE '2021-11-03', DATE '2021-11-17', 'Known', FALSE, 'test')$q$);
    PERFORM pg_temp.expect_fail('staging rule', 'BR-05 KEV due date before date added is rejected',
           $q$INSERT INTO stg_kev (cve_id, date_added, due_date, known_ransomware_use, forensic_triage_required, batch_id)
              VALUES ('CVE-2021-42013', DATE '2021-11-03', DATE '2021-10-01', 'Unknown', FALSE, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'KEV ransomware value must be Known/Unknown',
           $q$INSERT INTO stg_kev (cve_id, date_added, due_date, known_ransomware_use, forensic_triage_required, batch_id)
              VALUES ('CVE-2021-42014', DATE '2021-11-03', DATE '2021-11-17', 'maybe', FALSE, 'test')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'CPE row with NULL bounds cannot be staged twice',
           $q$INSERT INTO stg_cve_cpe (cve_id, cpe_criteria, cpe_vendor, cpe_product, batch_id)
              VALUES ('CVE-2000-0010', 'cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*', 'x', 'y', 't'),
                     ('CVE-2000-0010', 'cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*', 'x', 'y', 't')$q$, '23505');
    PERFORM pg_temp.expect_fail('staging rule', 'reference mapping rejects unknown match method',
           $q$INSERT INTO ref_software_product_map VALUES ('Nginx', 'F5', 'Web Server', 'f5', 'nginx', 'Guess', 'Confirmed', NULL)$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'batch log rejects unknown load type',
           $q$INSERT INTO etl_batch_log (batch_id, batch_date, load_type) VALUES ('x', DATE '2026-10-10', 'delta')$q$, '23514');
    PERFORM pg_temp.expect_fail('staging rule', 'step log rejects a step for an unregistered batch',
           $q$INSERT INTO etl_step_log (batch_id, layer, step_name) VALUES ('no-such-batch', 'staging', 'x')$q$, '23503');

END $tests$;


-- 3. Restore sequences, then report

SELECT count(*) AS sequences_restored FROM (
    SELECT CASE WHEN last_value IS NULL THEN setval(seq, start_value, FALSE)
                ELSE setval(seq, last_value, TRUE) END
    FROM saved_sequence) r;


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
        RAISE EXCEPTION '% of % DDL tests FAILED', v_failed, v_total;
    END IF;
    RAISE NOTICE 'All % DDL tests passed', v_total;
END $$;

ROLLBACK;
