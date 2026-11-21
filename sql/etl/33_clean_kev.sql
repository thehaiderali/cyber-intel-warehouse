/*
   33_clean_kev.sql
   raw_kev_document -> stg_kev -> cur_kev_catalog

   Cleaning rules
     Validate      CVE ID format (BR-01); dateAdded / dueDate must be dates;
                   dueDate must not be before dateAdded (BR-05)
     Standardise   trim + collapse whitespace in every text field
                   (' ISC BIND Data Processing Errors Vulnerability' -> no leading space);
                   knownRansomwareCampaignUse -> Known / Unknown;
                   forensicTriage Yes/No -> BOOLEAN
     De-duplicate  one row per CVE, latest dateAdded wins (DQ-DUP)
     Accumulate    incremental KEV files only hold new entries, so every clean
                   row is upserted into cur_kev_catalog (the full catalog)
*/

SET search_path = project_staging;

TRUNCATE stg_kev;

DROP TABLE IF EXISTS pg_temp.kev_work;
CREATE TEMP TABLE kev_work AS
SELECT e.ord                                                       AS record_no,
       e.v                                                         AS raw,
       e.v ->> 'cveID'                                             AS raw_cve_id,
       upper(btrim(e.v ->> 'cveID'))                               AS cve_id,
       e.v ->> 'vendorProject'                                     AS raw_vendor_project,
       fn_clean_text(e.v ->> 'vendorProject')                      AS vendor_project,
       e.v ->> 'product'                                           AS raw_product,
       fn_clean_text(e.v ->> 'product')                            AS product,
       e.v ->> 'vulnerabilityName'                                 AS raw_vulnerability_name,
       fn_clean_text(e.v ->> 'vulnerabilityName')                  AS vulnerability_name,
       fn_clean_text(e.v ->> 'shortDescription')                   AS short_description,
       CASE WHEN e.v ->> 'dateAdded' ~ '^\d{4}-\d{2}-\d{2}$' THEN (e.v ->> 'dateAdded')::DATE END AS date_added,
       CASE WHEN e.v ->> 'dueDate'   ~ '^\d{4}-\d{2}-\d{2}$' THEN (e.v ->> 'dueDate')::DATE   END AS due_date,
       fn_clean_text(e.v ->> 'requiredAction')                     AS required_action,
       e.v ->> 'knownRansomwareCampaignUse'                        AS raw_ransomware,
       CASE lower(btrim(e.v ->> 'knownRansomwareCampaignUse'))
            WHEN 'known' THEN 'Known' ELSE 'Unknown' END           AS known_ransomware_use,
       lower(btrim(coalesce(e.v ->> 'forensicTriage', 'no'))) IN ('yes', 'true', 'y') AS forensic_triage_required,
       fn_clean_text(e.v ->> 'notes')                              AS notes,
       CAST(NULL AS TEXT)                                          AS reject_rule,
       CAST(NULL AS TEXT)                                          AS reject_reason
FROM raw_kev_document d
CROSS JOIN LATERAL jsonb_array_elements(d.document -> 'vulnerabilities') WITH ORDINALITY AS e(v, ord);

UPDATE kev_work SET reject_rule = 'BR-01', reject_reason = 'CVE ID "' || coalesce(raw_cve_id, '') || '" is missing or malformed'
WHERE cve_id IS NULL OR cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$';

UPDATE kev_work SET reject_rule = 'DQ-NULL', reject_reason = 'dateAdded or dueDate missing / not a date'
WHERE reject_rule IS NULL AND (date_added IS NULL OR due_date IS NULL);

UPDATE kev_work SET reject_rule = 'BR-05', reject_reason = 'dueDate ' || due_date || ' is before dateAdded ' || date_added
WHERE reject_rule IS NULL AND due_date < date_added;

UPDATE kev_work w SET reject_rule = 'DQ-DUP', reject_reason = 'Duplicate CVE in the same KEV file - latest dateAdded kept'
FROM (SELECT record_no, row_number() OVER (PARTITION BY cve_id ORDER BY date_added DESC, record_no DESC) AS rn
      FROM kev_work WHERE reject_rule IS NULL) d
WHERE d.record_no = w.record_no AND d.rn > 1;

INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'KEV', raw_cve_id, reject_rule, reject_reason, raw
FROM kev_work
WHERE reject_rule IS NOT NULL;

INSERT INTO stg_kev (cve_id, vendor_project, product, vulnerability_name, short_description, date_added, due_date,
                     required_action, known_ransomware_use, forensic_triage_required, notes, batch_id)
SELECT cve_id, vendor_project, product, vulnerability_name, short_description, date_added, due_date,
       required_action, known_ransomware_use, forensic_triage_required, notes, :'batch_id'
FROM kev_work
WHERE reject_rule IS NULL;

INSERT INTO cur_kev_catalog AS c (cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
                                  required_action, known_ransomware_use, forensic_triage_required, first_batch_id, last_batch_id)
SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
       required_action, known_ransomware_use, forensic_triage_required, :'batch_id', :'batch_id'
FROM stg_kev
ON CONFLICT (cve_id) DO UPDATE
    SET vendor_project           = EXCLUDED.vendor_project,
        product                  = EXCLUDED.product,
        vulnerability_name       = EXCLUDED.vulnerability_name,
        date_added               = EXCLUDED.date_added,
        due_date                 = EXCLUDED.due_date,
        required_action          = EXCLUDED.required_action,
        known_ransomware_use     = EXCLUDED.known_ransomware_use,
        forensic_triage_required = EXCLUDED.forensic_triage_required,
        last_batch_id            = EXCLUDED.last_batch_id;

INSERT INTO etl_cleaning_stat (batch_id, source_name, column_name, cleaning_rule, rows_affected, example_before, example_after)
SELECT :'batch_id', 'KEV', col, rule, count(*), left((array_agg(before_value ORDER BY before_value, after_value))[1], 120), left((array_agg(after_value ORDER BY before_value, after_value))[1], 120)
FROM (
    SELECT 'row' AS col, 'Reject: ' || reject_rule AS rule, raw_cve_id AS before_value, '(rejected)' AS after_value
    FROM kev_work WHERE reject_rule IS NOT NULL
    UNION ALL
    SELECT 'vulnerability_name', 'Trim + collapse whitespace', '"' || raw_vulnerability_name || '"', '"' || vulnerability_name || '"'
    FROM kev_work WHERE raw_vulnerability_name IS DISTINCT FROM vulnerability_name
    UNION ALL
    SELECT 'vendor_project', 'Trim + collapse whitespace', '"' || raw_vendor_project || '"', '"' || vendor_project || '"'
    FROM kev_work WHERE raw_vendor_project IS DISTINCT FROM vendor_project
    UNION ALL
    SELECT 'product', 'Trim + collapse whitespace', '"' || raw_product || '"', '"' || product || '"'
    FROM kev_work WHERE raw_product IS DISTINCT FROM product
    UNION ALL
    SELECT 'known_ransomware_use', 'Map to Known / Unknown', raw_ransomware, known_ransomware_use
    FROM kev_work WHERE raw_ransomware IS DISTINCT FROM known_ransomware_use
    UNION ALL
    SELECT 'forensic_triage', 'Yes/No -> BOOLEAN', raw ->> 'forensicTriage', forensic_triage_required::TEXT
    FROM kev_work WHERE reject_rule IS NULL
) s
GROUP BY col, rule;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, rows_rejected, message)
SELECT :'batch_id', 'staging', 'Clean KEV catalog', 'stg_kev',
       count(*),
       count(*) FILTER (WHERE reject_rule IS NULL),
       count(*) FILTER (WHERE reject_rule IS NOT NULL),
       format('BR-01 %s, BR-05 %s, duplicates %s; KEV catalog now %s CVEs',
              count(*) FILTER (WHERE reject_rule = 'BR-01'),
              count(*) FILTER (WHERE reject_rule = 'BR-05'),
              count(*) FILTER (WHERE reject_rule = 'DQ-DUP'),
              (SELECT count(*) FROM cur_kev_catalog))
FROM kev_work;

DROP TABLE kev_work;
