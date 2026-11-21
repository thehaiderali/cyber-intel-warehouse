/*
   02_staging_ddl.sql
   Staging layer (schema project_staging).

   Table families
   etl_*   ETL audit: one row per batch and one row per pipeline step.
   raw_*   Landing tables. Source data loaded AS-IS (everything TEXT / JSONB),
           no cleaning. Truncated and reloaded for every batch (transient).
   stg_*   Cleaned, de-duplicated, typed data for the batch being processed.
           Also transient - rebuilt from raw_* every batch.
   ref_*   Persistent reference / mapping data maintained by the team
           (controlled vocabularies, software -> CPE product mapping).

   Sources
   NVD   CVE feed            JSON  (wrapper object, "vulnerabilities" array)
   EPSS  exploit scores      CSV   (first line is a "#model_version,score_date" comment)
   KEV   CISA KEV catalog    JSON  (wrapper object, "vulnerabilities" array)
   Cortexa asset inventory   CSV

   Run: psql -U postgres -d intel_dw -f sql/02_staging_ddl.sql
   Re-runnable: drops and recreates the staging objects.
*/

SET client_min_messages = warning;
SET search_path = project_staging;

-- 1. ETL audit

DROP TABLE IF EXISTS etl_step_log;
DROP TABLE IF EXISTS etl_batch_log;

CREATE TABLE etl_batch_log (
    batch_id        VARCHAR(40)  PRIMARY KEY,                -- 'full_load' or '2026-10-10_045631'
    batch_date      DATE         NOT NULL,                   -- snapshot / assessment date of the batch
    load_type       VARCHAR(20)  NOT NULL CHECK (load_type IN ('full', 'incremental')),
    status          VARCHAR(20)  NOT NULL DEFAULT 'Running'
                                 CHECK (status IN ('Running', 'Success', 'Failed')),
    started_at      TIMESTAMP    NOT NULL DEFAULT clock_timestamp(),
    finished_at     TIMESTAMP,
    notes           TEXT
);
COMMENT ON TABLE etl_batch_log IS 'One row per source batch processed. Acts as the load watermark: a batch with status Success is never reloaded.';

CREATE TABLE etl_step_log (
    step_log_id     BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id        VARCHAR(40)  NOT NULL REFERENCES etl_batch_log (batch_id),
    layer           VARCHAR(20)  NOT NULL CHECK (layer IN ('extract', 'staging', 'dimension', 'bridge', 'fact', 'quality')),
    step_name       VARCHAR(100) NOT NULL,
    target_table    VARCHAR(100),
    rows_in         BIGINT,
    rows_out        BIGINT,
    rows_rejected   BIGINT,
    status          VARCHAR(20)  NOT NULL DEFAULT 'Success',
    logged_at       TIMESTAMP    NOT NULL DEFAULT clock_timestamp(),
    message         TEXT
);
COMMENT ON TABLE etl_step_log IS 'Row counts per ETL step (input, output, rejected) - feeds the data cleaning report.';

-- 2. Raw landing tables (as-is copy of the source files)

DROP TABLE IF EXISTS raw_file_line;
DROP TABLE IF EXISTS raw_nvd_document;
DROP TABLE IF EXISTS raw_kev_document;
DROP TABLE IF EXISTS raw_epss;
DROP TABLE IF EXISTS raw_asset;

-- Line buffer used to bring pretty-printed JSON and the commented EPSS CSV
-- into the database without a client-side parser: every physical line of the
-- file becomes one row, in file order (line_no). The lines are then glued back
-- together (JSON) or split into fields (EPSS) inside SQL.
CREATE UNLOGGED TABLE raw_file_line (
    line_no         BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    line            TEXT
);
COMMENT ON TABLE raw_file_line IS 'Scratch buffer: one row per physical line of the file currently being extracted.';

CREATE TABLE raw_nvd_document (
    batch_id        VARCHAR(40)  PRIMARY KEY,
    source_file     TEXT         NOT NULL,
    document        JSONB        NOT NULL,                   -- whole NVD response, unmodified
    loaded_at       TIMESTAMP    NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE raw_kev_document (
    batch_id        VARCHAR(40)  PRIMARY KEY,
    source_file     TEXT         NOT NULL,
    document        JSONB        NOT NULL,                   -- whole KEV catalog, unmodified
    loaded_at       TIMESTAMP    NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE raw_epss (
    batch_id        VARCHAR(40)  NOT NULL,
    source_file     TEXT         NOT NULL,
    source_line_no  BIGINT       NOT NULL,
    cve             TEXT,
    epss            TEXT,
    percentile      TEXT,
    model_version   TEXT,                                    -- from the "#model_version:..." comment line
    score_date_raw  TEXT,                                    -- from the "...,score_date:..." comment line
    loaded_at       TIMESTAMP    NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (batch_id, source_line_no)
);

CREATE TABLE raw_asset (
    batch_id          VARCHAR(40),
    source_file       TEXT,
    source_row_no     BIGINT     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,   -- preserves file order for deterministic de-duplication
    asset_id          TEXT,
    hostname          TEXT,
    ip_address        TEXT,
    os_name           TEXT,
    os_version        TEXT,
    software_name     TEXT,
    software_version  TEXT,
    department        TEXT,
    owner             TEXT,
    criticality       TEXT,
    exposure          TEXT,
    environment       TEXT,
    location          TEXT,
    status            TEXT,
    loaded_at         TIMESTAMP  NOT NULL DEFAULT clock_timestamp()
);

-- 3. Reference data (persistent, maintained by the team)

DROP TABLE IF EXISTS ref_controlled_value;
DROP TABLE IF EXISTS ref_software_product_map;

-- Controlled vocabularies (BR-06). Source values are matched after
-- lower(trim()) so ' CRITICAL', 'critical' and 'Critical' all map to 'Critical'.
CREATE TABLE ref_controlled_value (
    domain          VARCHAR(40)  NOT NULL,                   -- e.g. 'criticality', 'exposure', 'environment'
    source_value    VARCHAR(100) NOT NULL,                   -- lower-case, trimmed
    standard_value  VARCHAR(100) NOT NULL,
    numeric_value   NUMERIC(6,2),                            -- e.g. criticality score 1..4
    PRIMARY KEY (domain, source_value)
);
COMMENT ON TABLE ref_controlled_value IS 'Standardisation dictionary: maps every accepted spelling of a code value to its standard form.';

-- Manual mapping between the names used in the asset inventory and the
-- vendor:product naming used by NVD CPE strings (BR-07).
CREATE TABLE ref_software_product_map (
    software_name       VARCHAR(255) NOT NULL,               -- standardised inventory name
    software_vendor     VARCHAR(255) NOT NULL,
    asset_type          VARCHAR(50)  NOT NULL,               -- Web Server, Database, ...
    cpe_vendor          VARCHAR(255) NOT NULL,
    cpe_product         VARCHAR(255) NOT NULL,
    match_method        VARCHAR(50)  NOT NULL CHECK (match_method IN ('Exact Name', 'Normalized Name', 'CPE', 'Manual Mapping')),
    match_confidence    VARCHAR(30)  NOT NULL CHECK (match_confidence IN ('Confirmed', 'Probable', 'Manual Review', 'Unmatched')),
    mapping_notes       TEXT,
    PRIMARY KEY (software_name, cpe_vendor, cpe_product)
);
COMMENT ON TABLE ref_software_product_map IS 'Bridges inventory software names to NVD CPE vendor/product. Seeds bridge_product_software_map.';

-- 4. Cleaned staging tables (one batch at a time)

DROP TABLE IF EXISTS stg_reject;
DROP TABLE IF EXISTS stg_asset;
DROP TABLE IF EXISTS stg_cve;
DROP TABLE IF EXISTS stg_cve_cwe;
DROP TABLE IF EXISTS stg_cve_cpe;
DROP TABLE IF EXISTS stg_epss;
DROP TABLE IF EXISTS stg_kev;

-- Quarantine for records that fail a business rule (BR-01 .. BR-06).
CREATE TABLE stg_reject (
    reject_id       BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id        VARCHAR(40)  NOT NULL,
    source_name     VARCHAR(20)  NOT NULL,                   -- NVD / EPSS / KEV / ASSET
    business_key    TEXT,                                    -- cve_id or asset_id as received
    rule_id         VARCHAR(10)  NOT NULL,                   -- BR-01 ...
    reject_reason   TEXT         NOT NULL,
    raw_record      JSONB,
    rejected_at     TIMESTAMP    NOT NULL DEFAULT clock_timestamp()
);
COMMENT ON TABLE stg_reject IS 'Records rejected or quarantined during cleansing, with the rule that failed. Persistent across batches.';

CREATE TABLE stg_asset (
    asset_id                VARCHAR(100) PRIMARY KEY,
    hostname                VARCHAR(255) NOT NULL,
    ip_address              VARCHAR(45),
    os_name                 VARCHAR(100),
    os_version              VARCHAR(50),
    software_name           VARCHAR(255) NOT NULL,
    software_version        VARCHAR(100) NOT NULL,          -- BR-04: versions stay text
    asset_type              VARCHAR(50),
    department_name         VARCHAR(100),
    asset_owner             VARCHAR(255),
    criticality_level       VARCHAR(20)  NOT NULL CHECK (criticality_level IN ('Critical', 'High', 'Medium', 'Low')),
    asset_criticality_score SMALLINT     NOT NULL CHECK (asset_criticality_score BETWEEN 1 AND 4),
    exposure_level          VARCHAR(30),
    internet_exposed_flag   BOOLEAN      NOT NULL,
    environment             VARCHAR(30),
    location_name           VARCHAR(100),
    asset_status            VARCHAR(30),
    active_flag             BOOLEAN      NOT NULL,
    source_row_no           BIGINT       NOT NULL,
    duplicate_count         INT          NOT NULL DEFAULT 1, -- how many raw rows collapsed into this one
    batch_id                VARCHAR(40)  NOT NULL
);

CREATE TABLE stg_cve (
    cve_id                  VARCHAR(30)  PRIMARY KEY,
    source_identifier       VARCHAR(255),
    vulnerability_status    VARCHAR(50),
    description_en          TEXT,
    published_at            TIMESTAMP    NOT NULL,
    last_modified_at        TIMESTAMP    NOT NULL,
    primary_cwe_code        VARCHAR(30),
    cvss_version            VARCHAR(5),
    cvss_base_score         NUMERIC(3,1) CHECK (cvss_base_score BETWEEN 0 AND 10),     -- BR-03
    cvss_base_severity      VARCHAR(20),
    cvss_vector_string      VARCHAR(255),
    attack_vector           VARCHAR(30),
    attack_complexity       VARCHAR(30),
    privileges_required     VARCHAR(30),
    user_interaction        VARCHAR(30),
    scope                   VARCHAR(30),
    confidentiality_impact  VARCHAR(30),
    integrity_impact        VARCHAR(30),
    availability_impact     VARCHAR(30),
    batch_id                VARCHAR(40)  NOT NULL
);

CREATE TABLE stg_cve_cwe (
    cve_id          VARCHAR(30)  NOT NULL,
    cwe_code        VARCHAR(30)  NOT NULL,
    source_name     VARCHAR(10)  NOT NULL,                   -- NVD / KEV
    batch_id        VARCHAR(40)  NOT NULL,
    PRIMARY KEY (cve_id, cwe_code)
);

CREATE TABLE stg_cve_cpe (
    stg_cve_cpe_id           BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id                   VARCHAR(30)  NOT NULL,
    cpe_criteria             TEXT         NOT NULL,          -- cpe:2.3:part:vendor:product:version:...
    cpe_part                 CHAR(1),                        -- a = application, o = OS, h = hardware
    cpe_vendor               VARCHAR(255) NOT NULL,
    cpe_product              VARCHAR(255) NOT NULL,
    cpe_version              VARCHAR(100),                   -- NULL when the criteria uses '*' / '-'
    version_start_including  VARCHAR(100),
    version_start_excluding  VARCHAR(100),
    version_end_including    VARCHAR(100),
    version_end_excluding    VARCHAR(100),
    batch_id                 VARCHAR(40)  NOT NULL
);
CREATE UNIQUE INDEX ux_stg_cve_cpe ON stg_cve_cpe
    (cve_id, cpe_criteria, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
    NULLS NOT DISTINCT;

CREATE TABLE stg_epss (
    cve_id          VARCHAR(30)  NOT NULL,
    score_date      DATE         NOT NULL,
    epss_score      NUMERIC(8,6) NOT NULL CHECK (epss_score BETWEEN 0 AND 1),          -- BR-02
    epss_percentile NUMERIC(8,6) NOT NULL CHECK (epss_percentile BETWEEN 0 AND 1),
    model_version   VARCHAR(30),
    batch_id        VARCHAR(40)  NOT NULL,
    PRIMARY KEY (cve_id, score_date)
);

CREATE TABLE stg_kev (
    cve_id                      VARCHAR(30)  PRIMARY KEY,
    vendor_project              VARCHAR(255),
    product                     VARCHAR(255),
    vulnerability_name          TEXT,
    short_description           TEXT,
    date_added                  DATE         NOT NULL,
    due_date                    DATE         NOT NULL,
    required_action             TEXT,
    known_ransomware_use        VARCHAR(20)  NOT NULL CHECK (known_ransomware_use IN ('Known', 'Unknown')),
    forensic_triage_required    BOOLEAN      NOT NULL,
    notes                       TEXT,
    batch_id                    VARCHAR(40)  NOT NULL,
    CHECK (due_date >= date_added)                                                     -- BR-05
);
