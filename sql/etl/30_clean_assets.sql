/*
   30_clean_assets.sql
   raw_asset -> stg_asset

   Cleaning rules
     Standardise text   trim, collapse spaces, map through ref_controlled_value
                        (' lahore ' / 'LAHORE' -> 'Lahore', 'PROD' -> 'Production')
     Handle NULLs       empty owner / department -> 'Unassigned';
                        invalid IP -> NULL (row kept, value quarantined)
     Validate           missing asset_id -> rejected (DQ-KEY);
                        criticality not in the controlled list -> rejected (BR-06)
     De-duplicate       one row per asset_id, first occurrence in the file wins
                        (DQ-DUP), later copies are logged in stg_reject
     Derive             criticality score 1-4, internet_exposed_flag, active_flag,
                        asset_type from the software mapping
     Types              software_version stays text (BR-04)
*/

SET search_path = project_staging;

TRUNCATE stg_asset;

DROP TABLE IF EXISTS pg_temp.asset_work;
CREATE TEMP TABLE asset_work AS
SELECT r.source_row_no,
       r.asset_id         AS raw_asset_id,
       r.hostname         AS raw_hostname,
       r.ip_address       AS raw_ip_address,
       r.os_name          AS raw_os_name,
       r.software_name    AS raw_software_name,
       r.department       AS raw_department,
       r.owner            AS raw_owner,
       r.criticality      AS raw_criticality,
       r.exposure         AS raw_exposure,
       r.environment      AS raw_environment,
       r.location         AS raw_location,
       r.status           AS raw_status,
       upper(fn_clean_text(r.asset_id))                                         AS asset_id,
       lower(fn_clean_text(r.hostname))                                         AS hostname,
       CASE WHEN fn_clean_text(r.ip_address) ~ '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
              OR fn_clean_text(r.ip_address) ~* '^[0-9a-f:]+:[0-9a-f:]*$'
            THEN fn_clean_text(r.ip_address) END                                AS ip_address,
       coalesce(os.standard_value, initcap(fn_clean_text(r.os_name)))           AS os_name,
       fn_clean_text(r.os_version)                                              AS os_version,
       coalesce(sw.standard_value, fn_clean_text(r.software_name))              AS software_name,
       fn_clean_text(r.software_version)                                        AS software_version,
       coalesce(dep.standard_value, initcap(fn_clean_text(r.department)), 'Unassigned') AS department_name,
       coalesce(lower(fn_clean_text(r.owner)), 'Unassigned')                    AS asset_owner,
       crit.standard_value                                                      AS criticality_level,
       crit.numeric_value::SMALLINT                                             AS asset_criticality_score,
       coalesce(exp.standard_value, initcap(fn_clean_text(r.exposure)))         AS exposure_level,
       coalesce(exp.numeric_value = 1, FALSE)                                   AS internet_exposed_flag,
       coalesce(env.standard_value, initcap(fn_clean_text(r.environment)))      AS environment,
       CASE WHEN lower(fn_clean_text(r.location)) ~ '^[a-z]{2}-[a-z]+-[0-9][a-z]?$'
            THEN lower(fn_clean_text(r.location))
            ELSE coalesce(loc.standard_value, initcap(fn_clean_text(r.location))) END AS location_name,
       coalesce(st.standard_value, initcap(fn_clean_text(r.status)))           AS asset_status,
       coalesce(st.numeric_value = 1, FALSE)                                    AS active_flag
FROM raw_asset r
LEFT JOIN ref_controlled_value os   ON os.domain   = 'os_name'       AND os.source_value   = lower(fn_clean_text(r.os_name))
LEFT JOIN ref_controlled_value sw   ON sw.domain   = 'software_name' AND sw.source_value   = lower(fn_clean_text(r.software_name))
LEFT JOIN ref_controlled_value dep  ON dep.domain  = 'department'    AND dep.source_value  = lower(fn_clean_text(r.department))
LEFT JOIN ref_controlled_value crit ON crit.domain = 'criticality'   AND crit.source_value = lower(fn_clean_text(r.criticality))
LEFT JOIN ref_controlled_value exp  ON exp.domain  = 'exposure'      AND exp.source_value  = lower(fn_clean_text(r.exposure))
LEFT JOIN ref_controlled_value env  ON env.domain  = 'environment'   AND env.source_value  = lower(fn_clean_text(r.environment))
LEFT JOIN ref_controlled_value loc  ON loc.domain  = 'location'      AND loc.source_value  = lower(fn_clean_text(r.location))
LEFT JOIN ref_controlled_value st   ON st.domain   = 'asset_status'  AND st.source_value   = lower(fn_clean_text(r.status));

ALTER TABLE asset_work ADD COLUMN reject_rule TEXT, ADD COLUMN reject_reason TEXT, ADD COLUMN dup_rank INT;

UPDATE asset_work SET reject_rule = 'DQ-KEY', reject_reason = 'Asset ID is missing'
WHERE asset_id IS NULL;

UPDATE asset_work SET reject_rule = 'BR-06', reject_reason = 'Criticality "' || raw_criticality || '" is not Critical/High/Medium/Low'
WHERE reject_rule IS NULL AND criticality_level IS NULL;

UPDATE asset_work SET reject_rule = 'DQ-NULL', reject_reason = 'Hostname, software name or software version is missing'
WHERE reject_rule IS NULL AND (hostname IS NULL OR software_name IS NULL OR software_version IS NULL);

UPDATE asset_work w SET dup_rank = d.rn
FROM (SELECT source_row_no, row_number() OVER (PARTITION BY asset_id ORDER BY source_row_no) AS rn
      FROM asset_work WHERE reject_rule IS NULL) d
WHERE d.source_row_no = w.source_row_no;

UPDATE asset_work SET reject_rule = 'DQ-DUP', reject_reason = 'Duplicate asset_id - first occurrence in the file kept'
WHERE reject_rule IS NULL AND dup_rank > 1;


-- Rejected and de-duplicated rows go to quarantine with the original values

INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'ASSET', w.raw_asset_id, w.reject_rule, w.reject_reason, to_jsonb(r) - 'loaded_at'
FROM asset_work w
JOIN raw_asset r USING (source_row_no)
WHERE w.reject_rule IS NOT NULL;

-- Field-level fix: invalid IP replaced by NULL, row kept
INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'ASSET', asset_id, 'DQ-FMT', 'Invalid IP address "' || raw_ip_address || '" set to NULL (row kept)',
       jsonb_build_object('ip_address', raw_ip_address)
FROM asset_work
WHERE reject_rule IS NULL AND ip_address IS NULL AND fn_clean_text(raw_ip_address) IS NOT NULL;


-- Load the clean rows

INSERT INTO stg_asset (asset_id, hostname, ip_address, os_name, os_version, software_name, software_version, asset_type,
                       department_name, asset_owner, criticality_level, asset_criticality_score, exposure_level,
                       internet_exposed_flag, environment, location_name, asset_status, active_flag,
                       source_row_no, duplicate_count, batch_id)
SELECT w.asset_id, w.hostname, w.ip_address, w.os_name, w.os_version, w.software_name, w.software_version,
       coalesce(m.asset_type, 'Other'),
       w.department_name, w.asset_owner, w.criticality_level, w.asset_criticality_score, w.exposure_level,
       w.internet_exposed_flag, w.environment, w.location_name, w.asset_status, w.active_flag,
       w.source_row_no,
       (SELECT count(*) FROM asset_work d WHERE d.asset_id = w.asset_id AND d.reject_rule IS DISTINCT FROM 'BR-06'
                                            AND d.reject_rule IS DISTINCT FROM 'DQ-KEY'),
       :'batch_id'
FROM asset_work w
LEFT JOIN LATERAL (SELECT asset_type FROM ref_software_product_map m
                   WHERE m.software_name = w.software_name LIMIT 1) m ON TRUE
WHERE w.reject_rule IS NULL;


-- Cleaning statistics (values changed per column) for the cleaning report

INSERT INTO etl_cleaning_stat (batch_id, source_name, column_name, cleaning_rule, rows_affected, example_before, example_after)
SELECT :'batch_id', 'ASSET', col, rule, count(*), (array_agg(before_value ORDER BY before_value, after_value))[1], (array_agg(after_value ORDER BY before_value, after_value))[1]
FROM (
    SELECT 'asset_id' AS col, 'Trim + upper case' AS rule, raw_asset_id AS before_value, asset_id AS after_value FROM asset_work WHERE raw_asset_id IS DISTINCT FROM asset_id AND asset_id IS NOT NULL
    UNION ALL SELECT 'hostname', 'Trim + lower case', raw_hostname, hostname FROM asset_work WHERE raw_hostname IS DISTINCT FROM hostname
    UNION ALL SELECT 'ip_address', 'Invalid IP -> NULL', raw_ip_address, '(NULL)' FROM asset_work WHERE ip_address IS NULL AND fn_clean_text(raw_ip_address) IS NOT NULL
    UNION ALL SELECT 'os_name', 'Map to controlled value', raw_os_name, os_name FROM asset_work WHERE raw_os_name IS DISTINCT FROM os_name
    UNION ALL SELECT 'software_name', 'Map to controlled value', raw_software_name, software_name FROM asset_work WHERE raw_software_name IS DISTINCT FROM software_name
    UNION ALL SELECT 'department', 'Map to controlled value', raw_department, department_name FROM asset_work WHERE raw_department IS DISTINCT FROM department_name AND fn_clean_text(raw_department) IS NOT NULL
    UNION ALL SELECT 'department', 'Missing -> Unassigned', raw_department, department_name FROM asset_work WHERE fn_clean_text(raw_department) IS NULL
    UNION ALL SELECT 'owner', 'Missing -> Unassigned', coalesce(raw_owner, '(NULL)'), asset_owner FROM asset_work WHERE fn_clean_text(raw_owner) IS NULL
    UNION ALL SELECT 'criticality', 'Map to controlled value', raw_criticality, criticality_level FROM asset_work WHERE raw_criticality IS DISTINCT FROM criticality_level AND criticality_level IS NOT NULL
    UNION ALL SELECT 'environment', 'Map to controlled value', raw_environment, environment FROM asset_work WHERE raw_environment IS DISTINCT FROM environment
    UNION ALL SELECT 'location', 'Trim + standardise case', raw_location, location_name FROM asset_work WHERE raw_location IS DISTINCT FROM location_name
    UNION ALL SELECT 'exposure', 'Map to controlled value', raw_exposure, exposure_level FROM asset_work WHERE raw_exposure IS DISTINCT FROM exposure_level
    UNION ALL SELECT 'status', 'Map to controlled value', raw_status, asset_status FROM asset_work WHERE raw_status IS DISTINCT FROM asset_status
    UNION ALL SELECT 'row', 'Remove duplicate asset_id', raw_asset_id, '(removed)' FROM asset_work WHERE reject_rule = 'DQ-DUP'
    UNION ALL SELECT 'row', 'Reject: ' || reject_rule, coalesce(nullif(raw_asset_id, ''), '(blank)') || ' / ' || raw_criticality, '(rejected)' FROM asset_work WHERE reject_rule IN ('BR-06', 'DQ-KEY', 'DQ-NULL')
) s
GROUP BY col, rule;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, rows_rejected, message)
SELECT :'batch_id', 'staging', 'Clean asset inventory', 'stg_asset',
       count(*),
       count(*) FILTER (WHERE reject_rule IS NULL),
       count(*) FILTER (WHERE reject_rule IS NOT NULL),
       format('duplicates removed %s, BR-06 rejects %s, missing key %s, invalid IPs nulled %s',
              count(*) FILTER (WHERE reject_rule = 'DQ-DUP'),
              count(*) FILTER (WHERE reject_rule = 'BR-06'),
              count(*) FILTER (WHERE reject_rule = 'DQ-KEY'),
              count(*) FILTER (WHERE reject_rule IS NULL AND ip_address IS NULL AND fn_clean_text(raw_ip_address) IS NOT NULL))
FROM asset_work
HAVING count(*) > 0;

DROP TABLE asset_work;
