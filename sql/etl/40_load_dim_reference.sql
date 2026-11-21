/*
   40_load_dim_reference.sql
   Small reference dimensions, loaded from the batch's staging data.
   New members get the next surrogate key; existing members are left unchanged.

   dim_cwe         new CWE codes from stg_cve_cwe
   dim_cvss        new CVSS version + vector + score combinations from stg_cve,
                   then cur_cve_score keeps the latest cvss_key per CVE
   dim_kev_status  new KEV flag / required action combinations from the KEV catalog
*/

SET search_path = project_dw, project_staging;


-- dim_cwe

WITH ins AS (
    INSERT INTO dim_cwe (cwe_code, cwe_description)
    SELECT DISTINCT s.cwe_code, 'Not in reference list'
    FROM stg_cve_cwe s
    WHERE NOT EXISTS (SELECT 1 FROM dim_cwe d WHERE d.cwe_code = s.cwe_code)
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'dimension', 'Load dim_cwe', 'dim_cwe',
       (SELECT count(DISTINCT cwe_code) FROM stg_cve_cwe), (SELECT count(*) FROM ins);


-- dim_cvss

WITH src AS (
    SELECT DISTINCT ON (cvss_version, cvss_vector_string, cvss_base_score)
           cvss_version, cvss_base_score, cvss_base_severity, attack_vector, attack_complexity, privileges_required,
           user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, cvss_vector_string
    FROM stg_cve
    WHERE cvss_version IS NOT NULL
    ORDER BY cvss_version, cvss_vector_string, cvss_base_score, cve_id
),
ins AS (
    INSERT INTO dim_cvss (cvss_version, base_score, base_severity, attack_vector, attack_complexity, privileges_required,
                          user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, vector_string)
    SELECT s.*
    FROM src s
    WHERE NOT EXISTS (SELECT 1 FROM dim_cvss d
                      WHERE d.cvss_version  IS NOT DISTINCT FROM s.cvss_version
                        AND d.vector_string IS NOT DISTINCT FROM s.cvss_vector_string
                        AND d.base_score    IS NOT DISTINCT FROM s.cvss_base_score)
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'dimension', 'Load dim_cvss', 'dim_cvss', (SELECT count(*) FROM src), (SELECT count(*) FROM ins);

-- latest CVSS per CVE (CVEs without CVSS point at the unknown member -1)
INSERT INTO cur_cve_score (cve_id, cvss_key, cvss_base_score, last_batch_id)
SELECT s.cve_id, coalesce(d.cvss_key, -1), s.cvss_base_score, :'batch_id'
FROM stg_cve s
LEFT JOIN dim_cvss d
       ON d.cvss_version  = s.cvss_version
      AND d.vector_string IS NOT DISTINCT FROM s.cvss_vector_string
      AND d.base_score    IS NOT DISTINCT FROM s.cvss_base_score
ON CONFLICT (cve_id) DO UPDATE
    SET cvss_key        = EXCLUDED.cvss_key,
        cvss_base_score = EXCLUDED.cvss_base_score,
        last_batch_id   = EXCLUDED.last_batch_id;


-- dim_kev_status

WITH src AS (
    SELECT DISTINCT TRUE AS is_kev_listed, known_ransomware_use, forensic_triage_required, required_action
    FROM cur_kev_catalog
),
ins AS (
    INSERT INTO dim_kev_status (is_kev_listed, known_ransomware_use, forensic_triage_required, required_action)
    SELECT s.*
    FROM src s
    WHERE NOT EXISTS (SELECT 1 FROM dim_kev_status d
                      WHERE d.is_kev_listed = s.is_kev_listed
                        AND d.known_ransomware_use     IS NOT DISTINCT FROM s.known_ransomware_use
                        AND d.forensic_triage_required IS NOT DISTINCT FROM s.forensic_triage_required
                        AND d.required_action          IS NOT DISTINCT FROM s.required_action)
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'dimension', 'Load dim_kev_status', 'dim_kev_status', (SELECT count(*) FROM src), (SELECT count(*) FROM ins);
