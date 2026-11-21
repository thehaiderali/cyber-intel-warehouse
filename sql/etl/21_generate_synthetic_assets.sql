/*
   21_generate_synthetic_assets.sql
   Synthetic data (Phase 2 option B), full load only.

   The Cortexa inventory file has 100 rows but only 20 distinct assets and
   almost no formatting problems. This script appends 130 synthetic assets to
   raw_asset (source_file = 'synthetic:21_generate_synthetic_assets.sql') so that
     * dim_asset has 100+ members, and
     * the cleaning rules have realistic dirty input to work on.

   Each synthetic asset reuses one of the real software/version/OS
   combinations, so it is matched against real NVD CVEs.
   Generation is deterministic (no random()), so every run produces the same rows.

   Injected data problems (by asset number n):
     n % 7  = 0   criticality in odd case/padding        ' high '
     n % 11 = 0   environment abbreviated                'PROD', 'dev '
     n % 13 = 0   department upper case                  'FINANCE'
     n % 9  = 0   hostname upper case with spaces        ' WEB-SYN-009 '
     n % 17 = 0   owner missing                          ''
     n % 19 = 0   invalid IP address                     '300.12.4.19'
     n % 23 = 0   criticality outside controlled list    'urgent'   -> rejected (BR-06)
     n % 8  = 0   software name spelled differently      'apache', 'NodeJS', 'k8s', 'REDIS'
     n % 31 = 0   asset id missing                       ''         -> rejected (BR-01)
     n % 10 = 0   the whole row is sent twice            duplicate
     on-premises locations in mixed case                 ' lahore ', 'LAHORE', 'Lahore'
*/

SET search_path = project_staging;

WITH combo AS (
    SELECT row_number() OVER (ORDER BY software_name, software_version) - 1 AS combo_no,
           software_name, software_version, os_name, os_version
    FROM (SELECT DISTINCT ON (software_name, software_version)
                 software_name, software_version, os_name, os_version
          FROM raw_asset
          WHERE source_file NOT LIKE 'synthetic:%'
          ORDER BY software_name, software_version, source_row_no) d
),
n AS (
    SELECT g AS n FROM generate_series(1, 130) AS g
),
base AS (
    SELECT n.n,
           c.software_name, c.software_version, c.os_name, c.os_version,
           (ARRAY['Data','DevOps','Engineering','Finance','Infrastructure','Network','Operations','Platform','Security'])[1 + n.n % 9]    AS department,
           (ARRAY['sec-team@corp.com','platform-team@corp.com','devops-team@corp.com','dba-team@corp.com','eng-team@corp.com','fin-ops@corp.com'])[1 + (n.n * 5) % 6] AS owner,
           (ARRAY['Low','Medium','Medium','High','Critical','Medium','Low','High'])[1 + (n.n * 3) % 8]                                AS criticality,
           (ARRAY['Internal','Internet-facing','DMZ','Internal','Isolated','Internet-facing'])[1 + (n.n * 7) % 6]                         AS exposure,
           (ARRAY['Production','Production','Staging','Test','Development','Production'])[1 + (n.n * 11) % 6]                           AS environment,
           (ARRAY['us-east-1a','us-west-2b','eu-west-1a','ap-southeast-1a','Lahore','Karachi','Islamabad'])[1 + (n.n * 13) % 7]           AS location,
           (ARRAY['Active','Active','Active','Active','Active','Active','Maintenance','Active','Active','Decommissioned'])[1 + (n.n * 17) % 10] AS status
    FROM n
    JOIN combo c ON c.combo_no = n.n % (SELECT count(*) FROM combo)
),
dirty AS (
    SELECT n,
           CASE WHEN n % 31 = 0 THEN '' ELSE 'AST-SYN-' || lpad(n::TEXT, 3, '0') END                                   AS asset_id,
           CASE WHEN n % 9 = 0
                THEN '  ' || upper(split_part(software_name, ' ', 1)) || '-SYN-' || lpad(n::TEXT, 3, '0') || ' '
                ELSE lower(split_part(software_name, ' ', 1)) || '-syn-' || lpad(n::TEXT, 3, '0') END                AS hostname,
           CASE WHEN n % 19 = 0 THEN '300.' || n % 250 || '.4.19'
                ELSE '10.' || (n / 250) || '.' || ((n * 7) % 250) || '.' || (n % 250 + 1) END                        AS ip_address,
           os_name, os_version,
           CASE WHEN n % 8 <> 0 THEN software_name                       -- another spelling of the same product
                WHEN software_name = 'Apache HTTP Server'   THEN 'apache'
                WHEN software_name = 'Node.js'              THEN 'NodeJS'
                WHEN software_name = 'MySQL'                THEN ' mysql '
                WHEN software_name = 'PostgreSQL'           THEN 'postgres'
                WHEN software_name = 'Kubernetes'           THEN 'k8s'
                WHEN software_name = 'Tomcat'               THEN 'Apache Tomcat'
                WHEN software_name = 'Microsoft SQL Server' THEN 'MSSQL'
                ELSE upper(software_name) END                                                                        AS software_name,
           software_version,
           CASE WHEN n % 13 = 0 THEN upper(department) ELSE department END                                          AS department,
           CASE WHEN n % 17 = 0 THEN '' ELSE owner END                                                              AS owner,
           CASE WHEN n % 23 = 0 THEN 'urgent'
                WHEN n % 7  = 0 THEN '  ' || lower(criticality) || ' '
                ELSE criticality END                                                                                AS criticality,
           exposure,
           CASE WHEN n % 11 = 0 THEN (ARRAY['PROD', 'dev ', 'Stage', 'qa'])[1 + (n / 11) % 4] ELSE environment END   AS environment,
           CASE location
                WHEN 'Lahore'    THEN (ARRAY[' lahore ', 'LAHORE', 'Lahore'])[1 + n % 3]
                WHEN 'Karachi'   THEN (ARRAY['karachi', ' KARACHI', 'Karachi'])[1 + n % 3]
                WHEN 'Islamabad' THEN (ARRAY['islamabad ', 'ISB', 'Islamabad'])[1 + n % 3]
                ELSE location END                                                                                   AS location,
           status
    FROM base
)
INSERT INTO raw_asset (batch_id, source_file, asset_id, hostname, ip_address, os_name, os_version, software_name,
                       software_version, department, owner, criticality, exposure, environment, location, status)
SELECT :'batch_id', 'synthetic:21_generate_synthetic_assets.sql',
       asset_id, hostname, ip_address, os_name, os_version, software_name,
       software_version, department, owner, criticality, exposure, environment, location, status
FROM dirty
CROSS JOIN LATERAL generate_series(1, CASE WHEN n % 10 = 0 THEN 2 ELSE 1 END) AS copies(c)
ORDER BY n, c;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'extract', 'Generate synthetic assets', 'raw_asset', 130, count(*),
       '130 synthetic assets, ' || (count(*) - 130) || ' duplicate rows injected'
FROM raw_asset
WHERE source_file LIKE 'synthetic:%';
