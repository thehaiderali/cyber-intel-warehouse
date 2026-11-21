/*
   62_load_fact_exposure.sql
   fact_asset_vulnerability_exposure: one row per CVE, affected asset,
   installed software/version and assessment (batch) date.

   How an exposure is found (no CVE is assigned by hand)
     1. installed software (inventory snapshot of the day)
        -> NVD product via bridge_product_software_map
     2. product -> CVEs via bridge_cve_product (current, non-rejected CVE versions)
     3. installed version checked against the CPE pin / range with fn_version_in_range
          in range                    -> exposure, version_match_flag = 1
          NVD gives no version info   -> exposure, version_match_flag = 0, 'Manual Review'
          out of range                -> no exposure
     4. match_confidence: 'Confirmed' when the version matched and the product
        mapping is confirmed, otherwise 'Probable' / 'Manual Review'

   Business key -> surrogate key lookups
     asset_id -> asset_key, software name/version -> software_key (via the inventory fact)
     cve_id   -> cve_key, vendor:product -> product_key (via the bridges)
     CVE measures and cvss_key / kev_status_key come from the vulnerability
     snapshot of the same date

   Derived measures
     risk_priority_score  Phase 1 formula: CVSS/10*35 + EPSS*30 + KEV*20
                          + criticality/4*10 + internet_exposed*5
     first detected       first assessment date the same CVE/asset/software appeared
     remediation due      KEV due date, otherwise first detected + risk band SLA
     remediation_status   asset Active -> Open, Maintenance -> In Progress,
                          Decommissioned -> Closed
     days_open            assessment date - first detected
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.inventory_today;
CREATE TEMP TABLE inventory_today AS
SELECT f.asset_key, f.software_key, a.asset_id, a.asset_status, f.asset_criticality_score, f.internet_exposed_flag,
       sw.software_version
FROM fact_asset_software_inventory_snapshot f
JOIN dim_asset    a  ON a.asset_key = f.asset_key
JOIN dim_software sw ON sw.software_key = f.software_key
WHERE f.snapshot_date_key = fn_date_key(:'batch_date'::DATE);

-- version check once per (installed software, CPE match), not once per asset
DROP TABLE IF EXISTS pg_temp.software_cve_match;
CREATE TEMP TABLE software_cve_match AS
SELECT m.software_key, b.cve_key, b.product_key, m.match_confidence AS mapping_confidence,
       fn_version_in_range(sw.software_version, b.cpe_version, b.version_start_including, b.version_start_excluding,
                           b.version_end_including, b.version_end_excluding) AS in_range
FROM bridge_product_software_map m
JOIN dim_software       sw ON sw.software_key = m.software_key
JOIN bridge_cve_product b  ON b.product_key   = m.product_key
JOIN dim_cve            c  ON c.cve_key       = b.cve_key AND c.is_current
                          AND c.vulnerability_status IS DISTINCT FROM 'Rejected'
WHERE m.is_active
  AND m.software_key IN (SELECT software_key FROM inventory_today);

DROP TABLE IF EXISTS pg_temp.software_cve;
CREATE TEMP TABLE software_cve AS
SELECT DISTINCT ON (software_key, cve_key)
       software_key, cve_key, product_key,
       bool_or(in_range IS TRUE) OVER w AS version_match,
       CASE WHEN bool_or(in_range IS TRUE) OVER w AND mapping_confidence = 'Confirmed' THEN 'Confirmed'
            WHEN bool_or(in_range IS TRUE) OVER w THEN 'Probable'
            ELSE 'Manual Review' END     AS match_confidence
FROM software_cve_match
WHERE in_range IS NOT FALSE
WINDOW w AS (PARTITION BY software_key, cve_key)
ORDER BY software_key, cve_key, (in_range IS TRUE) DESC, (mapping_confidence = 'Confirmed') DESC, product_key;

DROP TABLE IF EXISTS pg_temp.first_seen;
CREATE TEMP TABLE first_seen AS
SELECT c.cve_id, a.asset_id, f.software_key, min(f.first_detected_date_key) AS first_detected_date_key
FROM fact_asset_vulnerability_exposure f
JOIN dim_cve   c ON c.cve_key   = f.cve_key
JOIN dim_asset a ON a.asset_key = f.asset_key
WHERE f.assessment_date_key < fn_date_key(:'batch_date'::DATE)
GROUP BY c.cve_id, a.asset_id, f.software_key;

DROP TABLE IF EXISTS pg_temp.exposure_src;
CREATE TEMP TABLE exposure_src AS
SELECT i.asset_key, i.software_key, x.cve_key, x.product_key, x.match_confidence,
       x.version_match::INT                                      AS version_match_flag,
       i.asset_criticality_score, i.internet_exposed_flag,
       coalesce(v.cvss_key, -1)                                  AS cvss_key,
       coalesce(v.kev_status_key, 0)                             AS kev_status_key,
       v.epss_score, v.cvss_base_score,
       coalesce(v.kev_listed_flag, 0)                            AS kev_listed_flag,
       v.kev_due_date_key,
       coalesce(to_date(fs.first_detected_date_key::TEXT, 'YYYYMMDD'), :'batch_date'::DATE) AS first_detected_date,
       fn_exposure_risk_score(v.cvss_base_score, v.epss_score, coalesce(v.kev_listed_flag, 0),
                              i.asset_criticality_score, i.internet_exposed_flag) AS risk_priority_score,
       CASE i.asset_status WHEN 'Maintenance' THEN 'In Progress'
                           WHEN 'Decommissioned' THEN 'Closed'
                           ELSE 'Open' END                       AS remediation_status
FROM inventory_today i
JOIN software_cve x ON x.software_key = i.software_key
JOIN dim_cve      c ON c.cve_key = x.cve_key
LEFT JOIN fact_vulnerability_intelligence_snapshot v
       ON v.cve_key = x.cve_key AND v.assessment_date_key = fn_date_key(:'batch_date'::DATE)
LEFT JOIN first_seen fs
       ON fs.cve_id = c.cve_id AND fs.asset_id = i.asset_id AND fs.software_key = i.software_key;

INSERT INTO fact_asset_vulnerability_exposure
    (assessment_date_key, remediation_due_date_key, first_detected_date_key, cve_key, asset_key, software_key,
     product_key, cvss_key, kev_status_key, risk_band_key, match_confidence, version_match_flag,
     asset_criticality_score, internet_exposed_flag, epss_score, cvss_base_score, kev_listed_flag,
     risk_priority_score, remediation_status, days_open, batch_id)
SELECT fn_date_key(:'batch_date'::DATE),
       CASE WHEN e.kev_listed_flag = 1 AND e.kev_due_date_key > 0 THEN e.kev_due_date_key
            ELSE fn_date_key(e.first_detected_date + rb.remediation_sla_days) END,
       fn_date_key(e.first_detected_date),
       e.cve_key, e.asset_key, e.software_key, e.product_key, e.cvss_key, e.kev_status_key, rb.risk_band_key,
       e.match_confidence, e.version_match_flag, e.asset_criticality_score, e.internet_exposed_flag,
       e.epss_score, e.cvss_base_score, e.kev_listed_flag, e.risk_priority_score, e.remediation_status,
       :'batch_date'::DATE - e.first_detected_date,
       :'batch_id'
FROM exposure_src e
JOIN dim_risk_band rb ON e.risk_priority_score BETWEEN rb.minimum_score AND rb.maximum_score AND rb.risk_band_key > 0
ON CONFLICT (assessment_date_key, cve_key, asset_key, software_key) DO UPDATE
    SET remediation_due_date_key = EXCLUDED.remediation_due_date_key, product_key = EXCLUDED.product_key,
        cvss_key = EXCLUDED.cvss_key, kev_status_key = EXCLUDED.kev_status_key, risk_band_key = EXCLUDED.risk_band_key,
        match_confidence = EXCLUDED.match_confidence, version_match_flag = EXCLUDED.version_match_flag,
        epss_score = EXCLUDED.epss_score, cvss_base_score = EXCLUDED.cvss_base_score,
        kev_listed_flag = EXCLUDED.kev_listed_flag, risk_priority_score = EXCLUDED.risk_priority_score,
        remediation_status = EXCLUDED.remediation_status, days_open = EXCLUDED.days_open,
        batch_id = EXCLUDED.batch_id, loaded_at = clock_timestamp();

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'fact', 'Load fact_asset_vulnerability_exposure', 'fact_asset_vulnerability_exposure',
       (SELECT count(*) FROM software_cve_match),
       (SELECT count(*) FROM fact_asset_vulnerability_exposure WHERE assessment_date_key = fn_date_key(:'batch_date'::DATE)),
       format('CPE checks %s (in range %s, no version info %s, out of range %s); exposures: confirmed %s, probable %s, manual review %s',
              (SELECT count(*) FROM software_cve_match),
              (SELECT count(*) FROM software_cve_match WHERE in_range),
              (SELECT count(*) FROM software_cve_match WHERE in_range IS NULL),
              (SELECT count(*) FROM software_cve_match WHERE NOT in_range),
              (SELECT count(*) FROM exposure_src WHERE match_confidence = 'Confirmed'),
              (SELECT count(*) FROM exposure_src WHERE match_confidence = 'Probable'),
              (SELECT count(*) FROM exposure_src WHERE match_confidence = 'Manual Review'));

DROP TABLE inventory_today, software_cve_match, software_cve, first_seen, exposure_src;
