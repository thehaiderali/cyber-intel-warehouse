/*
   05_reporting_views.sql
   Reporting layer (schema project_reporting): one view per Phase 1 business
   question plus a KPI summary. Views read only project_dw.

   "Latest" = the most recent assessment / snapshot date in the facts.

   Q1  vw_q01_cve_risk_ranking            highest risk-priority CVEs
   Q2  vw_q02_critical_high_cves          Critical / High CVSS severity
   Q3  vw_q03_top_epss                    highest EPSS exploitation probability
   Q4  vw_q04_kev_cves                    CVEs in the CISA KEV catalog
   Q5  vw_q05_kev_remediation_due         KEV remediation overdue / approaching
   Q6  vw_q06_severity_distribution       CVEs per CVSS severity
   Q7  vw_q07_vendor_product_cves         vendors/products with most CVEs
   Q8  vw_q08_cwe_high_risk               most frequent CWEs among high-risk CVEs
   Q9  vw_q09_publication_kev_trend       CVE publications and KEV additions by month/quarter/year
   Q10 vw_q10_ransomware_kev              KEV CVEs used in ransomware campaigns
   Q11 vw_q11_asset_exposure              critical / internet-facing assets with most exposure
   Q12 vw_q12_remediation_workload        workload by department, owner, environment
   KPI vw_kpi_summary                     headline KPIs
       vw_daily_risk_trend                daily totals across all snapshots

   Run: psql -U postgres -d intel_dw -f sql/05_reporting_views.sql
*/

SET client_min_messages = warning;
SET search_path = project_reporting, project_dw;

DROP VIEW IF EXISTS vw_q01_cve_risk_ranking, vw_q02_critical_high_cves, vw_q03_top_epss, vw_q04_kev_cves,
                    vw_q05_kev_remediation_due, vw_q06_severity_distribution, vw_q07_vendor_product_cves,
                    vw_q08_cwe_high_risk, vw_q09_publication_kev_trend, vw_q10_ransomware_kev,
                    vw_q11_asset_exposure, vw_q12_remediation_workload, vw_kpi_summary, vw_daily_risk_trend,
                    vw_latest_cve_snapshot, vw_latest_exposure CASCADE;


-- Building blocks: the latest snapshot rows joined to their dimensions

CREATE VIEW vw_latest_cve_snapshot AS
SELECT ad.full_date                AS assessment_date,
       c.cve_id,
       c.description_en,
       c.vulnerability_status,
       c.primary_cwe_code,
       pd.full_date                AS published_date,
       cv.cvss_version,
       cv.base_severity            AS cvss_severity,
       cv.attack_vector,
       f.cvss_base_score,
       f.epss_score,
       f.epss_percentile,
       f.kev_listed_flag,
       f.ransomware_use_flag,
       ks.known_ransomware_use,
       ks.required_action,
       kad.full_date               AS kev_date_added,
       kdd.full_date               AS kev_due_date,
       f.days_to_kev_due_date,
       f.vulnerability_risk_score,
       rb.risk_band_name,
       rb.priority_rank,
       f.cve_key
FROM fact_vulnerability_intelligence_snapshot f
JOIN dim_date       ad  ON ad.date_key  = f.assessment_date_key
JOIN dim_date       pd  ON pd.date_key  = f.published_date_key
JOIN dim_date       kad ON kad.date_key = f.kev_date_added_key
JOIN dim_date       kdd ON kdd.date_key = f.kev_due_date_key
JOIN dim_cve        c   ON c.cve_key    = f.cve_key
JOIN dim_cvss       cv  ON cv.cvss_key  = f.cvss_key
JOIN dim_kev_status ks  ON ks.kev_status_key = f.kev_status_key
JOIN dim_risk_band  rb  ON rb.risk_band_key  = f.risk_band_key
WHERE f.assessment_date_key = (SELECT max(assessment_date_key) FROM fact_vulnerability_intelligence_snapshot);

CREATE VIEW vw_latest_exposure AS
SELECT ad.full_date                AS assessment_date,
       c.cve_id,
       a.asset_id,
       a.hostname,
       a.asset_type,
       a.environment,
       a.criticality_level,
       a.exposure_level,
       a.internet_exposed_flag,
       a.asset_owner,
       a.department_name,
       a.location_name,
       s.software_name,
       s.software_version,
       p.vendor_product_name,
       cv.base_severity            AS cvss_severity,
       f.cvss_base_score,
       f.epss_score,
       f.kev_listed_flag,
       f.match_confidence,
       f.version_match_flag,
       f.risk_priority_score,
       rb.risk_band_name,
       f.remediation_status,
       fd.full_date                AS first_detected_date,
       dd.full_date                AS remediation_due_date,
       f.days_open
FROM fact_asset_vulnerability_exposure f
JOIN dim_date      ad ON ad.date_key = f.assessment_date_key
JOIN dim_date      fd ON fd.date_key = f.first_detected_date_key
JOIN dim_date      dd ON dd.date_key = f.remediation_due_date_key
JOIN dim_cve       c  ON c.cve_key   = f.cve_key
JOIN dim_asset     a  ON a.asset_key = f.asset_key
JOIN dim_software  s  ON s.software_key = f.software_key
JOIN dim_product   p  ON p.product_key  = f.product_key
JOIN dim_cvss      cv ON cv.cvss_key    = f.cvss_key
JOIN dim_risk_band rb ON rb.risk_band_key = f.risk_band_key
WHERE f.assessment_date_key = (SELECT max(assessment_date_key) FROM fact_asset_vulnerability_exposure);


-- Q1 Which CVEs have the highest overall risk-priority score?
-- CVE score from the snapshot plus the highest asset exposure score for that CVE
CREATE VIEW vw_q01_cve_risk_ranking AS
SELECT rank() OVER (ORDER BY coalesce(e.max_exposure_score, 0) DESC, s.vulnerability_risk_score DESC) AS risk_rank,
       s.cve_id, s.cvss_severity, s.cvss_base_score, s.epss_score, s.kev_listed_flag,
       s.vulnerability_risk_score,
       e.max_exposure_score        AS highest_asset_risk_score,
       coalesce(e.affected_assets, 0) AS affected_assets,
       s.risk_band_name,
       left(s.description_en, 160) AS description
FROM vw_latest_cve_snapshot s
LEFT JOIN (SELECT cve_id, max(risk_priority_score) AS max_exposure_score, count(DISTINCT asset_id) AS affected_assets
           FROM vw_latest_exposure GROUP BY cve_id) e USING (cve_id);

-- Q2 Which vulnerabilities have Critical or High CVSS severity ratings?
CREATE VIEW vw_q02_critical_high_cves AS
SELECT cve_id, cvss_severity, cvss_version, cvss_base_score, attack_vector, epss_score, kev_listed_flag,
       published_date, left(description_en, 160) AS description
FROM vw_latest_cve_snapshot
WHERE cvss_severity IN ('CRITICAL', 'HIGH');

-- Q3 Which CVEs have the highest EPSS exploitation probability?
CREATE VIEW vw_q03_top_epss AS
SELECT rank() OVER (ORDER BY epss_score DESC NULLS LAST) AS epss_rank,
       cve_id, epss_score, epss_percentile, cvss_base_score, cvss_severity, kev_listed_flag
FROM vw_latest_cve_snapshot
WHERE epss_score IS NOT NULL;

-- Q4 Which vulnerabilities are listed in the CISA KEV catalog?
CREATE VIEW vw_q04_kev_cves AS
SELECT s.cve_id, s.kev_date_added, s.kev_due_date, s.known_ransomware_use, s.cvss_base_score, s.epss_score,
       (SELECT string_agg(DISTINCT p.vendor_product_name, ', ')
        FROM bridge_cve_product b JOIN dim_product p ON p.product_key = b.product_key
        WHERE b.cve_key = s.cve_key) AS affected_products,
       s.required_action
FROM vw_latest_cve_snapshot s
WHERE s.kev_listed_flag = 1;

-- Q5 Which KEV vulnerabilities have remediation dates that are overdue or approaching?
CREATE VIEW vw_q05_kev_remediation_due AS
SELECT cve_id, kev_date_added, kev_due_date, days_to_kev_due_date,
       CASE WHEN days_to_kev_due_date < 0   THEN 'Overdue'
            WHEN days_to_kev_due_date <= 14 THEN 'Due within 14 days'
            ELSE 'Not yet due' END AS due_status,
       known_ransomware_use, vulnerability_risk_score
FROM vw_latest_cve_snapshot
WHERE kev_listed_flag = 1 AND days_to_kev_due_date <= 14;

-- Q6 How many vulnerabilities fall into each CVSS severity category?
-- (watch-listed CVEs of the latest snapshot)
CREATE VIEW vw_q06_severity_distribution AS
SELECT coalesce(cvss_severity, 'NONE')                       AS cvss_severity,
       count(*)                                              AS cve_count,
       count(*) FILTER (WHERE kev_listed_flag = 1)           AS kev_cve_count,
       round(100.0 * count(*) / sum(count(*)) OVER (), 2)    AS pct_of_cves
FROM vw_latest_cve_snapshot
GROUP BY 1;

-- Q7 Which vendors and products have the largest number of identified vulnerabilities?
CREATE VIEW vw_q07_vendor_product_cves AS
SELECT p.source_vendor_name AS vendor, p.source_product_name AS product, p.vendor_product_name,
       count(DISTINCT c.cve_id) AS cve_count,
       rank() OVER (ORDER BY count(DISTINCT c.cve_id) DESC) AS product_rank
FROM bridge_cve_product b
JOIN dim_cve     c ON c.cve_key = b.cve_key AND c.is_current AND c.vulnerability_status IS DISTINCT FROM 'Rejected'
JOIN dim_product p ON p.product_key = b.product_key
GROUP BY p.source_vendor_name, p.source_product_name, p.vendor_product_name;

-- Q8 Which CWE weakness categories occur most frequently among high-risk vulnerabilities?
CREATE VIEW vw_q08_cwe_high_risk AS
SELECT w.cwe_code, w.cwe_description, count(DISTINCT s.cve_id) AS high_risk_cve_count
FROM vw_latest_cve_snapshot s
JOIN bridge_cve_cwe bw ON bw.cve_key = s.cve_key
JOIN dim_cwe        w  ON w.cwe_key  = bw.cwe_key
WHERE s.cvss_severity IN ('CRITICAL', 'HIGH') OR s.risk_band_name IN ('Critical', 'High') OR s.kev_listed_flag = 1
GROUP BY w.cwe_code, w.cwe_description;

-- Q9 How do CVE publications and KEV additions change by month, quarter and year?
CREATE VIEW vw_q09_publication_kev_trend AS
WITH pub AS (
    SELECT d.year_number, d.quarter_number, d.month_number, d.month_name, count(*) AS cves_published
    FROM dim_cve c JOIN dim_date d ON d.date_key = c.published_date_key
    WHERE c.is_current AND c.cve_key > 0
    GROUP BY 1, 2, 3, 4
), kev AS (
    SELECT d.year_number, d.quarter_number, d.month_number, d.month_name, count(*) AS kev_additions
    FROM vw_latest_cve_snapshot s JOIN dim_date d ON d.full_date = s.kev_date_added
    WHERE s.kev_listed_flag = 1
    GROUP BY 1, 2, 3, 4
)
SELECT year_number, quarter_number, month_number, month_name,
       coalesce(pub.cves_published, 0) AS cves_published,
       coalesce(kev.kev_additions, 0)  AS kev_additions
FROM pub FULL JOIN kev USING (year_number, quarter_number, month_number, month_name);

-- Q10 Which KEV vulnerabilities are associated with known ransomware campaigns?
CREATE VIEW vw_q10_ransomware_kev AS
SELECT cve_id, kev_date_added, kev_due_date, cvss_base_score, epss_score, vulnerability_risk_score,
       left(description_en, 160) AS description
FROM vw_latest_cve_snapshot
WHERE kev_listed_flag = 1 AND ransomware_use_flag = 1;

-- Q11 Which critical and internet-facing assets have the greatest vulnerability exposure?
CREATE VIEW vw_q11_asset_exposure AS
SELECT asset_id, hostname, criticality_level, exposure_level, environment, department_name,
       software_name || ' ' || software_version AS installed_software,
       count(*)                                       AS exposures,
       count(*) FILTER (WHERE kev_listed_flag = 1)    AS kev_exposures,
       count(*) FILTER (WHERE risk_band_name IN ('Critical', 'High')) AS high_priority_exposures,
       round(sum(risk_priority_score), 2)             AS total_risk_score,
       max(risk_priority_score)                       AS max_risk_score,
       rank() OVER (ORDER BY sum(risk_priority_score) DESC) AS exposure_rank
FROM vw_latest_exposure
WHERE criticality_level = 'Critical' OR internet_exposed_flag
GROUP BY asset_id, hostname, criticality_level, exposure_level, environment, department_name, software_name, software_version;

-- Q12 Which departments, owners or environments have the largest remediation workload?
CREATE VIEW vw_q12_remediation_workload AS
SELECT CASE WHEN GROUPING(department_name) = 0 THEN 'Department'
            WHEN GROUPING(asset_owner) = 0     THEN 'Owner'
            ELSE 'Environment' END                              AS dimension,
       coalesce(department_name, asset_owner, environment)     AS member,
       count(*)                                                 AS open_exposures,
       count(*) FILTER (WHERE risk_band_name IN ('Critical', 'High')) AS high_priority,
       count(*) FILTER (WHERE remediation_due_date < assessment_date) AS past_due,
       count(DISTINCT asset_id)                                 AS assets
FROM vw_latest_exposure
WHERE remediation_status IN ('Open', 'In Progress')
GROUP BY GROUPING SETS ((department_name), (asset_owner), (environment));

-- KPIs
CREATE VIEW vw_kpi_summary AS
SELECT (SELECT max(assessment_date) FROM vw_latest_cve_snapshot)                           AS assessment_date,
       (SELECT count(*) FROM dim_cve WHERE is_current AND cve_key > 0)                     AS total_cves_analyzed,
       (SELECT count(*) FROM vw_latest_cve_snapshot)                                       AS watch_listed_cves,
       (SELECT count(*) FROM vw_latest_cve_snapshot WHERE cvss_severity IN ('CRITICAL', 'HIGH')) AS critical_high_cves,
       (SELECT count(*) FROM vw_latest_cve_snapshot WHERE kev_listed_flag = 1)             AS kev_listed_cves,
       (SELECT count(*) FROM vw_latest_exposure)                                           AS asset_exposures,
       (SELECT count(*) FROM vw_latest_exposure WHERE risk_band_name IN ('Critical', 'High')) AS high_risk_exposures,
       (SELECT count(*) FROM vw_latest_cve_snapshot WHERE kev_listed_flag = 1 AND days_to_kev_due_date < 0) AS overdue_kev_items,
       (SELECT count(DISTINCT asset_id) FROM vw_latest_exposure
        WHERE criticality_level = 'Critical' AND internet_exposed_flag
          AND risk_band_name IN ('Critical', 'High'))                                      AS critical_internet_assets_high_priority;

-- Daily trend across all snapshots
CREATE VIEW vw_daily_risk_trend AS
SELECT d.full_date AS assessment_date,
       v.cves, v.kev_cves, v.avg_cve_risk,
       e.exposures, e.high_risk_exposures, e.total_exposure_risk
FROM (SELECT assessment_date_key, count(*) AS cves, sum(kev_listed_flag) AS kev_cves,
             round(avg(vulnerability_risk_score), 2) AS avg_cve_risk
      FROM fact_vulnerability_intelligence_snapshot GROUP BY 1) v
JOIN dim_date d ON d.date_key = v.assessment_date_key
LEFT JOIN (SELECT f.assessment_date_key, count(*) AS exposures,
                  count(*) FILTER (WHERE rb.risk_band_name IN ('Critical', 'High')) AS high_risk_exposures,
                  round(sum(f.risk_priority_score), 2) AS total_exposure_risk
           FROM fact_asset_vulnerability_exposure f JOIN dim_risk_band rb USING (risk_band_key)
           GROUP BY 1) e USING (assessment_date_key);
