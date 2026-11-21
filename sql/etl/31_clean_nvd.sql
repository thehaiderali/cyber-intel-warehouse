/*
   31_clean_nvd.sql
   raw_nvd_document -> stg_cve, stg_cve_cwe, stg_cve_cpe

   Cleaning rules
     Validate        CVE ID must match CVE-YYYY-NNNN+ (BR-01), published and
                     lastModified must be valid timestamps (DQ-NULL)
     Remove          CVEs rejected by NVD (vulnStatus = 'Rejected') that the
                     warehouse has never loaded (DQ-REJ). A CVE that is already
                     in dim_cve keeps flowing so its status change is recorded.
     De-duplicate    one row per CVE, latest lastModified wins (DQ-DUP)
     Flatten         nested JSON -> columns; English description; CWE list;
                     vulnerable CPE matches split into vendor/product/version
     Choose CVSS     v3.1 -> v3.0 -> v4.0 -> v2.0, NVD "Primary" score first;
                     score outside 0-10 is quarantined and set to NULL (BR-03)
     Handle NULLs    missing English description -> 'No English description available';
                     CPE version '*' / '-' -> NULL (meaning "any version")
     Standardise     trim / collapse whitespace in text, upper-case CWE codes,
                     lower-case CPE vendor/product, unescape CPE characters
     Types           text -> TIMESTAMP, NUMERIC(3,1)
*/

SET search_path = project_staging;

TRUNCATE stg_cve, stg_cve_cwe, stg_cve_cpe;


-- 1. One row per CVE record in the file

DROP TABLE IF EXISTS pg_temp.nvd_work;
CREATE TEMP TABLE nvd_work AS
SELECT e.ord                                               AS record_no,
       e.v -> 'cve'                                        AS c,
       e.v -> 'cve' ->> 'id'                               AS raw_cve_id,
       upper(btrim(e.v -> 'cve' ->> 'id'))                 AS cve_id,
       e.v -> 'cve' ->> 'vulnStatus'                       AS vulnerability_status,
       CASE WHEN e.v -> 'cve' ->> 'published' ~ '^\d{4}-\d{2}-\d{2}T'
            THEN (e.v -> 'cve' ->> 'published')::TIMESTAMP END     AS published_at,
       CASE WHEN e.v -> 'cve' ->> 'lastModified' ~ '^\d{4}-\d{2}-\d{2}T'
            THEN (e.v -> 'cve' ->> 'lastModified')::TIMESTAMP END  AS last_modified_at,
       CAST(NULL AS TEXT)                                  AS reject_rule,
       CAST(NULL AS TEXT)                                  AS reject_reason
FROM raw_nvd_document d
CROSS JOIN LATERAL jsonb_array_elements(d.document -> 'vulnerabilities') WITH ORDINALITY AS e(v, ord);

UPDATE nvd_work SET reject_rule = 'BR-01', reject_reason = 'CVE ID "' || coalesce(raw_cve_id, '(missing)') || '" is missing or malformed'
WHERE cve_id IS NULL OR cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$';

UPDATE nvd_work SET reject_rule = 'DQ-NULL', reject_reason = 'published / lastModified missing or not a timestamp'
WHERE reject_rule IS NULL AND (published_at IS NULL OR last_modified_at IS NULL);

UPDATE nvd_work w SET reject_rule = 'DQ-REJ', reject_reason = 'Rejected by NVD and never loaded into the warehouse'
WHERE reject_rule IS NULL
  AND vulnerability_status = 'Rejected'
  AND NOT EXISTS (SELECT 1 FROM project_dw.dim_cve d WHERE d.cve_id = w.cve_id);

UPDATE nvd_work w SET reject_rule = 'DQ-DUP', reject_reason = 'Duplicate CVE in the same file - latest lastModified kept'
FROM (SELECT record_no,
             row_number() OVER (PARTITION BY cve_id ORDER BY last_modified_at DESC, record_no DESC) AS rn
      FROM nvd_work WHERE reject_rule IS NULL) d
WHERE d.record_no = w.record_no AND d.rn > 1;

INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'NVD', raw_cve_id, reject_rule, reject_reason,
       -- keep the identifying fields only; the whole record is large
       jsonb_build_object('id', c -> 'id', 'vulnStatus', c -> 'vulnStatus',
                          'published', c -> 'published', 'lastModified', c -> 'lastModified')
FROM nvd_work
WHERE reject_rule IS NOT NULL;


-- 2. CVE attributes + chosen CVSS metric

DROP TABLE IF EXISTS pg_temp.cve_flat;
CREATE TEMP TABLE cve_flat AS
SELECT w.record_no,
       w.cve_id,
       fn_clean_text(w.c ->> 'sourceIdentifier')                         AS source_identifier,
       w.vulnerability_status,
       des.raw_description,
       fn_clean_text(des.raw_description)                                AS description_en,
       w.published_at,
       w.last_modified_at,
       cv.metric_key,
       cv.metric ->> 'type'                                              AS metric_type,
       cv.metric -> 'cvssData' ->> 'version'                             AS cvss_version,
       CASE WHEN cv.metric -> 'cvssData' ->> 'baseScore' ~ '^-?[0-9]+(\.[0-9]+)?$'
            THEN (cv.metric -> 'cvssData' ->> 'baseScore')::NUMERIC END  AS raw_score,
       upper(coalesce(cv.metric -> 'cvssData' ->> 'baseSeverity', cv.metric ->> 'baseSeverity')) AS cvss_base_severity,
       cv.metric -> 'cvssData' ->> 'vectorString'                        AS cvss_vector_string,
       coalesce(cv.metric -> 'cvssData' ->> 'attackVector',     cv.metric -> 'cvssData' ->> 'accessVector')     AS attack_vector,
       coalesce(cv.metric -> 'cvssData' ->> 'attackComplexity', cv.metric -> 'cvssData' ->> 'accessComplexity') AS attack_complexity,
       cv.metric -> 'cvssData' ->> 'privilegesRequired'                  AS privileges_required,
       coalesce(cv.metric -> 'cvssData' ->> 'userInteraction',
                CASE cv.metric ->> 'userInteractionRequired' WHEN 'true' THEN 'REQUIRED' WHEN 'false' THEN 'NONE' END) AS user_interaction,
       cv.metric -> 'cvssData' ->> 'scope'                               AS scope,
       coalesce(cv.metric -> 'cvssData' ->> 'confidentialityImpact', cv.metric -> 'cvssData' ->> 'vulnConfidentialityImpact') AS confidentiality_impact,
       coalesce(cv.metric -> 'cvssData' ->> 'integrityImpact',       cv.metric -> 'cvssData' ->> 'vulnIntegrityImpact')       AS integrity_impact,
       coalesce(cv.metric -> 'cvssData' ->> 'availabilityImpact',    cv.metric -> 'cvssData' ->> 'vulnAvailabilityImpact')    AS availability_impact
FROM nvd_work w
LEFT JOIN LATERAL (
    SELECT x.d ->> 'value' AS raw_description
    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.c -> 'descriptions') = 'array' THEN w.c -> 'descriptions' ELSE '[]' END) AS x(d)
    WHERE x.d ->> 'lang' = 'en'
    LIMIT 1
) des ON TRUE
LEFT JOIN LATERAL (
    SELECT p.metric_key, m.metric
    FROM (VALUES ('cvssMetricV31', 1), ('cvssMetricV30', 2), ('cvssMetricV40', 3), ('cvssMetricV2', 4)) AS p(metric_key, priority)
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(w.c -> 'metrics' -> p.metric_key) = 'array' THEN w.c -> 'metrics' -> p.metric_key ELSE '[]' END
    ) WITH ORDINALITY AS m(metric, o)
    WHERE m.metric ? 'cvssData'                      -- ssvc entries have no CVSS data
    ORDER BY p.priority, (m.metric ->> 'type' = 'Primary') DESC, m.o
    LIMIT 1
) cv ON TRUE
WHERE w.reject_rule IS NULL;

-- BR-03: quarantine scores outside 0-10, keep the CVE without a score
INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'NVD', cve_id, 'BR-03', 'CVSS base score ' || raw_score || ' outside 0-10, score set to NULL (CVE kept)',
       jsonb_build_object('cvss_version', cvss_version, 'baseScore', raw_score, 'vector', cvss_vector_string)
FROM cve_flat
WHERE raw_score IS NOT NULL AND raw_score NOT BETWEEN 0 AND 10;


-- 3. Weaknesses (CWE)

DROP TABLE IF EXISTS pg_temp.cwe_flat;
CREATE TEMP TABLE cwe_flat AS
SELECT w.cve_id,
       wk.value                                             AS raw_cwe,
       CASE WHEN btrim(wk.value) ~* '^cwe-[0-9]+$' THEN upper(btrim(wk.value))
            WHEN btrim(wk.value) ~* '^nvd-cwe-other$'  THEN 'NVD-CWE-Other'
            WHEN btrim(wk.value) ~* '^nvd-cwe-noinfo$' THEN 'NVD-CWE-noinfo'
       END                                                  AS cwe_code,
       wk.is_primary,
       wk.is_nvd,
       wk.o
FROM nvd_work w
CROSS JOIN LATERAL (
    SELECT dsc.d ->> 'value' AS value,
           (wn.x ->> 'type' = 'Primary')        AS is_primary,
           (wn.x ->> 'source' = 'nvd@nist.gov') AS is_nvd,
           wn.o * 100 + dsc.o                   AS o
    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.c -> 'weaknesses') = 'array' THEN w.c -> 'weaknesses' ELSE '[]' END) WITH ORDINALITY AS wn(x, o)
    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(wn.x -> 'description') = 'array' THEN wn.x -> 'description' ELSE '[]' END) WITH ORDINALITY AS dsc(d, o)
) wk
WHERE w.reject_rule IS NULL;

INSERT INTO stg_cve_cwe (cve_id, cwe_code, source_name, batch_id)
SELECT DISTINCT cve_id, cwe_code, 'NVD', :'batch_id'
FROM cwe_flat
WHERE cwe_code IS NOT NULL;


-- 4. Load stg_cve

INSERT INTO stg_cve (cve_id, source_identifier, vulnerability_status, description_en, published_at, last_modified_at,
                     primary_cwe_code, cvss_version, cvss_base_score, cvss_base_severity, cvss_vector_string,
                     attack_vector, attack_complexity, privileges_required, user_interaction, scope,
                     confidentiality_impact, integrity_impact, availability_impact, batch_id)
SELECT f.cve_id, f.source_identifier, f.vulnerability_status,
       coalesce(f.description_en, 'No English description available'),
       f.published_at, f.last_modified_at,
       (SELECT c.cwe_code FROM cwe_flat c
        WHERE c.cve_id = f.cve_id AND c.cwe_code IS NOT NULL
        ORDER BY c.is_primary DESC, c.is_nvd DESC, c.o LIMIT 1),
       f.cvss_version,
       CASE WHEN f.raw_score BETWEEN 0 AND 10 THEN round(f.raw_score, 1) END,
       CASE WHEN f.raw_score BETWEEN 0 AND 10 THEN f.cvss_base_severity END,
       f.cvss_vector_string,
       f.attack_vector, f.attack_complexity, f.privileges_required, f.user_interaction, f.scope,
       f.confidentiality_impact, f.integrity_impact, f.availability_impact,
       :'batch_id'
FROM cve_flat f;


-- 5. Vulnerable CPE matches (affected products and version ranges)

DROP TABLE IF EXISTS pg_temp.cpe_flat;
CREATE TEMP TABLE cpe_flat AS
SELECT w.cve_id,
       x.m ->> 'criteria'                                                       AS cpe_criteria,
       -- split on ':' but not on an escaped '\:'
       string_to_array(replace(x.m ->> 'criteria', '\:', chr(1)), ':')         AS parts,
       nullif(btrim(x.m ->> 'versionStartIncluding'), '')                      AS version_start_including,
       nullif(btrim(x.m ->> 'versionStartExcluding'), '')                      AS version_start_excluding,
       nullif(btrim(x.m ->> 'versionEndIncluding'), '')                        AS version_end_including,
       nullif(btrim(x.m ->> 'versionEndExcluding'), '')                        AS version_end_excluding
FROM nvd_work w
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(w.c -> 'configurations') = 'array' THEN w.c -> 'configurations' ELSE '[]' END) AS cf(cfg)
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(cf.cfg -> 'nodes') = 'array' THEN cf.cfg -> 'nodes' ELSE '[]' END) AS nd(node)
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(nd.node -> 'cpeMatch') = 'array' THEN nd.node -> 'cpeMatch' ELSE '[]' END) AS x(m)
WHERE w.reject_rule IS NULL
  AND (x.m ->> 'vulnerable')::BOOLEAN
  AND x.m ->> 'criteria' LIKE 'cpe:2.3:%';

-- CPE escapes characters with a backslash ('node\.js' style); remove it
CREATE OR REPLACE FUNCTION pg_temp.cpe_part(p_part TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT nullif(lower(regexp_replace(replace(p_part, chr(1), ':'), '\\(.)', '\1', 'g')), '')
$$;

INSERT INTO stg_cve_cpe (cve_id, cpe_criteria, cpe_part, cpe_vendor, cpe_product, cpe_version,
                         version_start_including, version_start_excluding, version_end_including, version_end_excluding, batch_id)
SELECT cve_id, cpe_criteria,
       pg_temp.cpe_part(parts[3]),
       pg_temp.cpe_part(parts[4]),
       pg_temp.cpe_part(parts[5]),
       CASE WHEN parts[6] IN ('*', '-', '') THEN NULL ELSE pg_temp.cpe_part(parts[6]) END,
       version_start_including, version_start_excluding, version_end_including, version_end_excluding,
       :'batch_id'
FROM cpe_flat
WHERE pg_temp.cpe_part(parts[4]) IS NOT NULL AND pg_temp.cpe_part(parts[5]) IS NOT NULL
ON CONFLICT DO NOTHING;


-- 6. Cleaning statistics and step log

INSERT INTO etl_cleaning_stat (batch_id, source_name, column_name, cleaning_rule, rows_affected, example_before, example_after)
SELECT :'batch_id', 'NVD', col, rule, count(*), left((array_agg(before_value ORDER BY before_value, after_value))[1], 120), left((array_agg(after_value ORDER BY before_value, after_value))[1], 120)
FROM (
    SELECT 'row' AS col, 'Reject: ' || reject_rule AS rule, raw_cve_id AS before_value, '(rejected)' AS after_value
    FROM nvd_work WHERE reject_rule IS NOT NULL
    UNION ALL
    SELECT 'description_en', 'Trim + collapse whitespace', raw_description, description_en
    FROM cve_flat WHERE raw_description IS DISTINCT FROM description_en AND description_en IS NOT NULL
    UNION ALL
    SELECT 'description_en', 'Missing -> default text', '(NULL)', 'No English description available'
    FROM cve_flat WHERE description_en IS NULL
    UNION ALL
    SELECT 'cvss', 'No CVSS metric -> unknown CVSS member', cve_id, '(cvss_key -1)'
    FROM cve_flat WHERE cvss_version IS NULL
    UNION ALL
    SELECT 'cvss', 'Chosen CVSS version ' || cvss_version, metric_key || ' ' || coalesce(metric_type, ''), cvss_version
    FROM cve_flat WHERE cvss_version IS NOT NULL
    UNION ALL
    SELECT 'cvss_base_score', 'Out of range -> NULL (BR-03)', raw_score::TEXT, '(NULL)'
    FROM cve_flat WHERE raw_score NOT BETWEEN 0 AND 10
    UNION ALL
    SELECT 'cwe_code', 'Standardise CWE code', raw_cwe, cwe_code
    FROM cwe_flat WHERE raw_cwe IS DISTINCT FROM cwe_code AND cwe_code IS NOT NULL
    UNION ALL
    SELECT 'cwe_code', 'Unrecognised CWE value dropped', raw_cwe, '(dropped)'
    FROM cwe_flat WHERE cwe_code IS NULL
    UNION ALL
    SELECT 'cpe_version', 'Wildcard version -> NULL (any version)', cpe_criteria, '(NULL)'
    FROM cpe_flat WHERE parts[6] IN ('*', '-', '')
) s
GROUP BY col, rule;

INSERT INTO etl_cleaning_stat (batch_id, source_name, column_name, cleaning_rule, rows_affected, example_before, example_after)
SELECT :'batch_id', 'NVD', 'cpe_match', 'Remove duplicate CPE match', (SELECT count(*) FROM cpe_flat) - (SELECT count(*) FROM stg_cve_cpe), NULL, NULL
WHERE (SELECT count(*) FROM cpe_flat) > (SELECT count(*) FROM stg_cve_cpe);

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, rows_rejected, message)
SELECT :'batch_id', 'staging', 'Clean NVD CVEs', 'stg_cve',
       (SELECT count(*) FROM nvd_work),
       (SELECT count(*) FROM stg_cve),
       (SELECT count(*) FROM nvd_work WHERE reject_rule IS NOT NULL),
       format('malformed id %s, rejected by NVD %s, duplicates %s, CWE links %s, CPE matches %s',
              (SELECT count(*) FROM nvd_work WHERE reject_rule = 'BR-01'),
              (SELECT count(*) FROM nvd_work WHERE reject_rule = 'DQ-REJ'),
              (SELECT count(*) FROM nvd_work WHERE reject_rule = 'DQ-DUP'),
              (SELECT count(*) FROM stg_cve_cwe),
              (SELECT count(*) FROM stg_cve_cpe));

DROP TABLE nvd_work, cve_flat, cwe_flat, cpe_flat;
