/*
   10_seed_reference_data.sql
   One-time seed data. Run once after the DDL, before the first batch.
   Re-runnable (upserts).

   1. Controlled vocabularies used to standardise asset text (BR-06)
   2. Inventory software -> NVD CPE product mapping (BR-07)
   3. dim_date calendar 1985-01-01 .. 2035-12-31
   4. dim_risk_band bands and remediation targets
   5. "Unknown" member (key -1) in every dimension, plus the "Not KEV listed" member

   Run: psql -U postgres -d intel_dw -v ON_ERROR_STOP=1 -f sql/etl/10_seed_reference_data.sql
*/

SET client_min_messages = warning;
SET search_path = project_staging, project_dw;

-- 1. Controlled vocabularies
-- source_value is the lower-case, trimmed, single-spaced spelling found in
-- source files; standard_value is what the warehouse stores.

INSERT INTO ref_controlled_value (domain, source_value, standard_value, numeric_value) VALUES
    ('criticality', 'critical',        'Critical', 4),
    ('criticality', 'crit',            'Critical', 4),
    ('criticality', 'high',            'High',     3),
    ('criticality', 'hi',              'High',     3),
    ('criticality', 'medium',          'Medium',   2),
    ('criticality', 'med',             'Medium',   2),
    ('criticality', 'moderate',        'Medium',   2),
    ('criticality', 'low',             'Low',      1),

    ('exposure', 'internet-facing',    'Internet-facing', 1),
    ('exposure', 'internet facing',    'Internet-facing', 1),
    ('exposure', 'external',           'Internet-facing', 1),
    ('exposure', 'public',             'Internet-facing', 1),
    ('exposure', 'dmz',                'DMZ',             1),
    ('exposure', 'internal',           'Internal',        0),
    ('exposure', 'isolated',           'Isolated',        0),
    ('exposure', 'air-gapped',         'Isolated',        0),

    ('environment', 'production',      'Production',  NULL),
    ('environment', 'prod',            'Production',  NULL),
    ('environment', 'prd',             'Production',  NULL),
    ('environment', 'staging',         'Staging',     NULL),
    ('environment', 'stage',           'Staging',     NULL),
    ('environment', 'stg',             'Staging',     NULL),
    ('environment', 'test',            'Test',        NULL),
    ('environment', 'testing',         'Test',        NULL),
    ('environment', 'qa',              'Test',        NULL),
    ('environment', 'development',     'Development', NULL),
    ('environment', 'dev',             'Development', NULL),

    ('asset_status', 'active',         'Active',         1),
    ('asset_status', 'in service',     'Active',         1),
    ('asset_status', 'maintenance',    'Maintenance',    0),
    ('asset_status', 'decommissioned', 'Decommissioned', 0),
    ('asset_status', 'retired',        'Decommissioned', 0),

    ('department', 'data',             'Data',           NULL),
    ('department', 'devops',           'DevOps',         NULL),
    ('department', 'dev ops',          'DevOps',         NULL),
    ('department', 'engineering',      'Engineering',    NULL),
    ('department', 'finance',          'Finance',        NULL),
    ('department', 'infrastructure',   'Infrastructure', NULL),
    ('department', 'network',          'Network',        NULL),
    ('department', 'networking',       'Network',        NULL),
    ('department', 'operations',       'Operations',     NULL),
    ('department', 'ops',              'Operations',     NULL),
    ('department', 'platform',         'Platform',       NULL),
    ('department', 'security',         'Security',       NULL),
    ('department', 'secops',           'Security',       NULL),

    ('os_name', 'ubuntu server',             'Ubuntu Server',            NULL),
    ('os_name', 'ubuntu',                    'Ubuntu Server',            NULL),
    ('os_name', 'red hat enterprise linux',  'Red Hat Enterprise Linux', NULL),
    ('os_name', 'rhel',                      'Red Hat Enterprise Linux', NULL),
    ('os_name', 'debian',                    'Debian',                   NULL),
    ('os_name', 'centos',                    'CentOS',                   NULL),
    ('os_name', 'alpine linux',              'Alpine Linux',             NULL),
    ('os_name', 'alpine',                    'Alpine Linux',             NULL),
    ('os_name', 'amazon linux',              'Amazon Linux',             NULL),
    ('os_name', 'windows server',            'Windows Server',           NULL),

    ('software_name', 'apache http server',   'Apache HTTP Server',   NULL),
    ('software_name', 'apache',               'Apache HTTP Server',   NULL),
    ('software_name', 'httpd',                'Apache HTTP Server',   NULL),
    ('software_name', 'tomcat',               'Tomcat',               NULL),
    ('software_name', 'apache tomcat',        'Tomcat',               NULL),
    ('software_name', 'mysql',                'MySQL',                NULL),
    ('software_name', 'node.js',              'Node.js',              NULL),
    ('software_name', 'nodejs',               'Node.js',              NULL),
    ('software_name', 'node',                 'Node.js',              NULL),
    ('software_name', 'kubernetes',           'Kubernetes',           NULL),
    ('software_name', 'k8s',                  'Kubernetes',           NULL),
    ('software_name', 'docker',               'Docker',               NULL),
    ('software_name', 'redis',                'Redis',                NULL),
    ('software_name', 'postgresql',           'PostgreSQL',           NULL),
    ('software_name', 'postgres',             'PostgreSQL',           NULL),
    ('software_name', 'logstash',             'Logstash',             NULL),
    ('software_name', 'prometheus',           'Prometheus',           NULL),
    ('software_name', 'openvpn',              'OpenVPN',              NULL),
    ('software_name', 'microsoft sql server', 'Microsoft SQL Server', NULL),
    ('software_name', 'mssql',                'Microsoft SQL Server', NULL),
    ('software_name', 'sql server',           'Microsoft SQL Server', NULL),

    -- on-premises sites (cloud zones such as 'us-east-1a' are kept lower-case)
    ('location', 'lahore',             'Lahore',    NULL),
    ('location', 'lahore dc',          'Lahore',    NULL),
    ('location', 'lhr',                'Lahore',    NULL),
    ('location', 'karachi',            'Karachi',   NULL),
    ('location', 'khi',                'Karachi',   NULL),
    ('location', 'islamabad',          'Islamabad', NULL),
    ('location', 'isb',                'Islamabad', NULL)
ON CONFLICT (domain, source_value) DO UPDATE
    SET standard_value = EXCLUDED.standard_value,
        numeric_value  = EXCLUDED.numeric_value;


-- 2. Software -> CPE product mapping
-- MySQL and Docker are published under two CPE vendors in NVD; both are mapped.

INSERT INTO ref_software_product_map
    (software_name, software_vendor, asset_type, cpe_vendor, cpe_product, match_method, match_confidence, mapping_notes) VALUES
    ('Apache HTTP Server',   'Apache Software Foundation', 'Web Server',         'apache',     'http_server', 'Manual Mapping', 'Confirmed', 'Inventory name differs from CPE product name'),
    ('Tomcat',               'Apache Software Foundation', 'Application Server', 'apache',     'tomcat',      'Normalized Name', 'Confirmed', NULL),
    ('MySQL',                'Oracle',                     'Database',           'oracle',     'mysql',       'Normalized Name', 'Confirmed', 'Current CPE vendor'),
    ('MySQL',                'Oracle',                     'Database',           'mysql',      'mysql',       'Normalized Name', 'Probable',  'Legacy CPE vendor used for older CVEs'),
    ('Node.js',              'OpenJS Foundation',          'Application Runtime','nodejs',     'node.js',     'Exact Name',      'Confirmed', NULL),
    ('Kubernetes',           'CNCF',                       'Container Platform', 'kubernetes', 'kubernetes',  'Exact Name',      'Confirmed', NULL),
    ('Docker',               'Docker Inc.',                'Container Platform', 'docker',     'docker',      'Exact Name',      'Confirmed', NULL),
    ('Docker',               'Docker Inc.',                'Container Platform', 'mobyproject','moby',        'Manual Mapping',  'Probable',  'Docker Engine is built from the Moby project'),
    ('Redis',                'Redis Ltd.',                 'Database',           'redis',      'redis',       'Exact Name',      'Confirmed', NULL),
    ('PostgreSQL',           'PostgreSQL Global Development Group', 'Database',  'postgresql', 'postgresql',  'Exact Name',      'Confirmed', NULL),
    ('Logstash',             'Elastic',                    'Log Pipeline',       'elastic',    'logstash',    'Normalized Name', 'Confirmed', NULL),
    ('Prometheus',           'Prometheus Authors',         'Monitoring',         'prometheus', 'prometheus',  'Exact Name',      'Confirmed', NULL),
    ('OpenVPN',              'OpenVPN Inc.',               'VPN Gateway',        'openvpn',    'openvpn',     'Exact Name',      'Confirmed', NULL),
    ('Microsoft SQL Server', 'Microsoft',                  'Database',           'microsoft',  'sql_server',  'Manual Mapping',  'Confirmed', 'Inventory version 2019 matches the CPE version token')
ON CONFLICT (software_name, cpe_vendor, cpe_product) DO UPDATE
    SET software_vendor  = EXCLUDED.software_vendor,
        asset_type       = EXCLUDED.asset_type,
        match_method     = EXCLUDED.match_method,
        match_confidence = EXCLUDED.match_confidence,
        mapping_notes    = EXCLUDED.mapping_notes;


-- 3. dim_date (date_key -1 = unknown date)

INSERT INTO dim_date (date_key, full_date, day_number, day_name, week_number, month_number, month_name, quarter_number, year_number, is_weekend)
VALUES (-1, NULL, NULL, 'Unknown', NULL, NULL, 'Unknown', NULL, NULL, NULL)
ON CONFLICT (date_key) DO NOTHING;

INSERT INTO dim_date (date_key, full_date, day_number, day_name, week_number, month_number, month_name, quarter_number, year_number, is_weekend)
SELECT to_char(d, 'YYYYMMDD')::INTEGER,
       d::DATE,
       EXTRACT(DAY FROM d),
       trim(to_char(d, 'Day')),
       EXTRACT(WEEK FROM d),
       EXTRACT(MONTH FROM d),
       trim(to_char(d, 'Month')),
       EXTRACT(QUARTER FROM d),
       EXTRACT(YEAR FROM d),
       EXTRACT(ISODOW FROM d) IN (6, 7)
FROM generate_series(DATE '1985-01-01', DATE '2035-12-31', INTERVAL '1 day') AS g(d)
ON CONFLICT (date_key) DO NOTHING;


-- 4. dim_risk_band
-- Scores are 0-100 with 2 decimals, so the bands do not overlap or leave gaps.
-- SLA = target days to remediate a non-KEV finding (KEV findings use the CISA due date).

INSERT INTO dim_risk_band (risk_band_key, risk_band_name, minimum_score, maximum_score, priority_rank, remediation_sla_days) VALUES
    (-1, 'Unknown',  -1.00,  -1.00, 99,  0),
    ( 1, 'Critical', 70.00, 100.00,  1, 15),
    ( 2, 'High',     50.00,  69.99,  2, 30),
    ( 3, 'Medium',   30.00,  49.99,  3, 60),
    ( 4, 'Low',       0.00,  29.99,  4, 90)
ON CONFLICT (risk_band_key) DO UPDATE
    SET risk_band_name       = EXCLUDED.risk_band_name,
        minimum_score        = EXCLUDED.minimum_score,
        maximum_score        = EXCLUDED.maximum_score,
        priority_rank        = EXCLUDED.priority_rank,
        remediation_sla_days = EXCLUDED.remediation_sla_days;


-- 5. Unknown members (key -1) and fixed members

INSERT INTO dim_cve (cve_key, cve_id, source_identifier, vulnerability_status, description_en,
                     published_date_key, last_modified_date_key, record_source, row_hash, effective_start_date)
VALUES (-1, 'Unknown', NULL, 'Unknown', 'Unknown CVE', -1, -1, 'System', md5('unknown'), DATE '1900-01-01')
ON CONFLICT (cve_key) DO NOTHING;

INSERT INTO dim_product (product_key, vendor_name, product_name, vendor_product_name, source_vendor_name, source_product_name, normalization_status)
VALUES (-1, 'unknown', 'unknown', 'unknown:unknown', 'Unknown', 'Unknown', 'Unknown')
ON CONFLICT (product_key) DO NOTHING;

INSERT INTO dim_software (software_key, software_name, software_vendor, software_version, normalized_software_name, normalized_vendor_name, normalization_status)
VALUES (-1, 'Unknown', 'Unknown', 'Unknown', 'unknown', 'unknown', 'Unknown')
ON CONFLICT (software_key) DO NOTHING;

INSERT INTO dim_asset (asset_key, asset_id, hostname, row_hash, effective_start_date)
VALUES (-1, 'Unknown', 'Unknown', md5('unknown'), DATE '1900-01-01')
ON CONFLICT (asset_key) DO NOTHING;

INSERT INTO dim_cvss (cvss_key, cvss_version, base_score, base_severity, vector_string)
VALUES (-1, NULL, NULL, 'NONE', NULL)
ON CONFLICT (cvss_key) DO NOTHING;

INSERT INTO dim_cwe (cwe_key, cwe_code, cwe_description)
VALUES (-1, 'Unknown', 'No weakness information')
ON CONFLICT (cwe_key) DO NOTHING;

-- Names of the most common weaknesses (MITRE CWE Top 25 and NVD placeholders).
-- CWE codes first seen in the NVD feed without a name here get 'Not in reference list'.
INSERT INTO dim_cwe (cwe_code, cwe_description) VALUES
    ('NVD-CWE-Other',  'Other (NVD: weakness not in the CWE list used by NVD)'),
    ('NVD-CWE-noinfo', 'Insufficient Information (NVD)'),
    ('CWE-20',  'Improper Input Validation'),
    ('CWE-22',  'Path Traversal'),
    ('CWE-77',  'Command Injection'),
    ('CWE-78',  'OS Command Injection'),
    ('CWE-79',  'Cross-site Scripting (XSS)'),
    ('CWE-89',  'SQL Injection'),
    ('CWE-94',  'Code Injection'),
    ('CWE-119', 'Improper Restriction of Operations within the Bounds of a Memory Buffer'),
    ('CWE-120', 'Classic Buffer Overflow'),
    ('CWE-125', 'Out-of-bounds Read'),
    ('CWE-190', 'Integer Overflow or Wraparound'),
    ('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor'),
    ('CWE-269', 'Improper Privilege Management'),
    ('CWE-276', 'Incorrect Default Permissions'),
    ('CWE-284', 'Improper Access Control'),
    ('CWE-287', 'Improper Authentication'),
    ('CWE-306', 'Missing Authentication for Critical Function'),
    ('CWE-352', 'Cross-Site Request Forgery (CSRF)'),
    ('CWE-362', 'Race Condition'),
    ('CWE-400', 'Uncontrolled Resource Consumption'),
    ('CWE-416', 'Use After Free'),
    ('CWE-434', 'Unrestricted Upload of File with Dangerous Type'),
    ('CWE-476', 'NULL Pointer Dereference'),
    ('CWE-502', 'Deserialization of Untrusted Data'),
    ('CWE-611', 'XML External Entity (XXE) Reference'),
    ('CWE-639', 'Authorization Bypass Through User-Controlled Key'),
    ('CWE-770', 'Allocation of Resources Without Limits or Throttling'),
    ('CWE-787', 'Out-of-bounds Write'),
    ('CWE-798', 'Use of Hard-coded Credentials'),
    ('CWE-862', 'Missing Authorization'),
    ('CWE-863', 'Incorrect Authorization'),
    ('CWE-918', 'Server-Side Request Forgery (SSRF)')
ON CONFLICT (cwe_code) DO UPDATE SET cwe_description = EXCLUDED.cwe_description;

INSERT INTO dim_kev_status (kev_status_key, is_kev_listed, known_ransomware_use, forensic_triage_required, required_action)
VALUES (-1, FALSE, 'Unknown', NULL, 'Unknown')
ON CONFLICT (kev_status_key) DO NOTHING;

INSERT INTO dim_kev_status (kev_status_key, is_kev_listed, known_ransomware_use, forensic_triage_required, required_action)
VALUES (0, FALSE, 'Not Applicable', FALSE, NULL)
ON CONFLICT (kev_status_key) DO NOTHING;

-- risk bands use fixed keys 1-4: move the identity past them
SELECT setval(pg_get_serial_sequence('project_dw.dim_risk_band', 'risk_band_key'),
              (SELECT max(risk_band_key) FROM project_dw.dim_risk_band));
