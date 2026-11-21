/*
   32_clean_epss.sql
   raw_epss -> stg_epss

   Cleaning rules
     Parse        score date and model version from the '#model_version:...,score_date:...'
                  comment line; if missing, the batch date is used
     Validate     CVE ID format (BR-01); epss / percentile numeric and in 0-1 (BR-02)
     De-duplicate one score per CVE per score date, first line wins (DQ-DUP)
     Types        text -> DATE, NUMERIC(8,6)
*/

SET search_path = project_staging;

TRUNCATE stg_epss;

DROP TABLE IF EXISTS pg_temp.epss_work;
CREATE TEMP TABLE epss_work AS
SELECT r.source_line_no,
       r.cve                                                            AS raw_cve,
       r.epss                                                           AS raw_epss,
       r.percentile                                                     AS raw_percentile,
       upper(btrim(r.cve))                                              AS cve_id,
       coalesce(substring(r.score_date_raw FROM '^(\d{4}-\d{2}-\d{2})')::DATE, :'batch_date'::DATE) AS score_date,
       fn_clean_text(r.model_version)                                   AS model_version,
       CASE WHEN btrim(r.epss) ~ '^[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$' THEN btrim(r.epss)::NUMERIC END             AS epss_score,
       CASE WHEN btrim(r.percentile) ~ '^[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$' THEN btrim(r.percentile)::NUMERIC END AS epss_percentile,
       CAST(NULL AS TEXT)                                               AS reject_rule,
       CAST(NULL AS TEXT)                                               AS reject_reason
FROM raw_epss r;

UPDATE epss_work SET reject_rule = 'BR-01', reject_reason = 'CVE ID "' || coalesce(raw_cve, '') || '" is missing or malformed'
WHERE cve_id IS NULL OR cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$';

UPDATE epss_work SET reject_rule = 'BR-02', reject_reason = 'EPSS "' || coalesce(raw_epss, '') || '" / percentile "' || coalesce(raw_percentile, '') || '" not a number between 0 and 1'
WHERE reject_rule IS NULL
  AND (epss_score IS NULL OR epss_percentile IS NULL
       OR epss_score NOT BETWEEN 0 AND 1 OR epss_percentile NOT BETWEEN 0 AND 1);

UPDATE epss_work w SET reject_rule = 'DQ-DUP', reject_reason = 'Duplicate CVE in the same EPSS file - first line kept'
FROM (SELECT source_line_no, row_number() OVER (PARTITION BY cve_id, score_date ORDER BY source_line_no) AS rn
      FROM epss_work WHERE reject_rule IS NULL) d
WHERE d.source_line_no = w.source_line_no AND d.rn > 1;

INSERT INTO stg_reject (batch_id, source_name, business_key, rule_id, reject_reason, raw_record)
SELECT :'batch_id', 'EPSS', raw_cve, reject_rule, reject_reason,
       jsonb_build_object('line', source_line_no, 'cve', raw_cve, 'epss', raw_epss, 'percentile', raw_percentile)
FROM epss_work
WHERE reject_rule IS NOT NULL;

INSERT INTO stg_epss (cve_id, score_date, epss_score, epss_percentile, model_version, batch_id)
SELECT cve_id, score_date, round(epss_score, 6), round(epss_percentile, 6), model_version, :'batch_id'
FROM epss_work
WHERE reject_rule IS NULL;

INSERT INTO etl_cleaning_stat (batch_id, source_name, column_name, cleaning_rule, rows_affected, example_before, example_after)
SELECT :'batch_id', 'EPSS', col, rule, count(*), (array_agg(before_value ORDER BY before_value, after_value))[1], (array_agg(after_value ORDER BY before_value, after_value))[1]
FROM (
    SELECT 'row' AS col, 'Reject: ' || reject_rule AS rule, raw_cve || ',' || raw_epss AS before_value, '(rejected)' AS after_value
    FROM epss_work WHERE reject_rule IS NOT NULL
    UNION ALL
    SELECT 'score_date', 'Parsed from comment line', NULL, min(score_date)::TEXT FROM epss_work HAVING count(*) > 0
    UNION ALL
    SELECT 'epss / percentile', 'Text -> NUMERIC(8,6)', raw_epss, round(epss_score, 6)::TEXT
    FROM epss_work WHERE reject_rule IS NULL AND raw_epss <> round(epss_score, 6)::TEXT
) s
GROUP BY col, rule;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, rows_rejected, message)
SELECT :'batch_id', 'staging', 'Clean EPSS scores', 'stg_epss',
       count(*),
       count(*) FILTER (WHERE reject_rule IS NULL),
       count(*) FILTER (WHERE reject_rule IS NOT NULL),
       format('score date %s, model %s, BR-01 %s, BR-02 %s, duplicates %s',
              min(score_date), min(model_version),
              count(*) FILTER (WHERE reject_rule = 'BR-01'),
              count(*) FILTER (WHERE reject_rule = 'BR-02'),
              count(*) FILTER (WHERE reject_rule = 'DQ-DUP'))
FROM epss_work;

DROP TABLE epss_work;
