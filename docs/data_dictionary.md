# Data Dictionary - project_dw

Source: `sql/03_dw_ddl.sql`. Schema `project_dw` holds 9 dimensions, 3 bridge tables and 3 fact tables.

## Conventions

- Every dimension has a surrogate key (`BIGINT` identity) and keeps its business key for traceability.
- `dim_date` uses a smart key in `YYYYMMDD` format.
- `dim_asset` surrogate keys start at 1001 (`asset_id` AST-APACHE-01 -> `asset_key` 1001).
- Key `-1` is the reserved "Unknown / Not applicable" member in every dimension, so fact foreign keys are never NULL.
- `dim_cve` and `dim_asset` are SCD Type 2 (`effective_start_date`, `effective_end_date`, `is_current`). Only one current row per business key.
- Fact flags are `SMALLINT` 0/1 so they can be summed (for example `SUM(kev_listed_flag)`).

---

## Dimensions

### dim_date
Calendar dimension. Role-playing: published, last modified, KEV added, KEV due, snapshot and assessment dates.

| Column | Type | Description |
|---|---|---|
| date_key (PK) | INTEGER | YYYYMMDD, -1 = unknown date |
| full_date | DATE | Calendar date (unique). NULL only for the unknown member |
| day_number | SMALLINT | Day of month |
| day_name | VARCHAR(10) | Day name |
| week_number | SMALLINT | ISO week |
| month_number | SMALLINT | Month number |
| month_name | VARCHAR(10) | Month name |
| quarter_number | SMALLINT | Quarter |
| year_number | SMALLINT | Year |
| is_weekend | BOOLEAN | Saturday or Sunday |

### dim_cve (SCD Type 2)
One row per version of a CVE. A new version is created when NVD modifies the CVE.

| Column | Type | Description |
|---|---|---|
| cve_key (PK) | BIGINT | Surrogate key |
| cve_id | VARCHAR(30) | Business key, e.g. CVE-2021-41773 |
| source_identifier | VARCHAR(255) | NVD source identifier |
| vulnerability_status | VARCHAR(50) | NVD status |
| description_en | TEXT | English description |
| primary_cwe_code | VARCHAR(30) | Main weakness code |
| published_date_key (FK) | INTEGER | -> dim_date |
| last_modified_date_key (FK) | INTEGER | -> dim_date |
| last_modified_at | TIMESTAMP | Exact NVD lastModified, drives change detection |
| record_source | VARCHAR(20) | Default 'NVD' |
| row_hash | CHAR(32) | md5 of tracked attributes |
| effective_start_date | DATE | SCD2 version start |
| effective_end_date | DATE | SCD2 version end, default 9999-12-31 |
| is_current | BOOLEAN | TRUE for the current version |

### dim_product
Affected vendor/product as named by NVD CPE strings.

| Column | Type | Description |
|---|---|---|
| product_key (PK) | BIGINT | Surrogate key |
| vendor_name | VARCHAR(255) | Normalised CPE vendor, e.g. apache |
| product_name | VARCHAR(255) | Normalised CPE product, e.g. http_server |
| vendor_product_name | VARCHAR(511) | Unique, e.g. apache:http_server |
| source_vendor_name | VARCHAR(255) | Display form, e.g. Apache |
| source_product_name | VARCHAR(255) | Display form, e.g. Http Server |
| cpe_part | CHAR(1) | a / o / h |
| normalization_status | VARCHAR(30) | CPE or Unknown |

### dim_software
Installed software product and version found in the asset inventory.

| Column | Type | Description |
|---|---|---|
| software_key (PK) | BIGINT | Surrogate key |
| software_name | VARCHAR(255) | As recorded in the inventory |
| software_vendor | VARCHAR(255) | Vendor |
| software_version | VARCHAR(100) | Kept as text (BR-04) |
| normalized_software_name | VARCHAR(255) | Standardised name |
| normalized_vendor_name | VARCHAR(255) | Standardised vendor |
| normalization_status | VARCHAR(30) | Mapped / Unmapped / Unknown |

Unique on (`normalized_software_name`, `software_version`).

### dim_asset (SCD Type 2)
Tracks owner, department, criticality, exposure, environment and location changes.

| Column | Type | Description |
|---|---|---|
| asset_key (PK) | BIGINT | Surrogate key, starts at 1001 |
| asset_id | VARCHAR(100) | Business key, e.g. AST-APACHE-01 |
| hostname | VARCHAR(255) | Host name |
| ip_address | VARCHAR(45) | IP address |
| asset_type | VARCHAR(50) | Type of asset |
| os_name, os_version | VARCHAR | Operating system |
| environment | VARCHAR(30) | e.g. Production |
| criticality_level | VARCHAR(20) | Controlled criticality value (BR-06) |
| asset_criticality_score | SMALLINT | Numeric criticality |
| exposure_level | VARCHAR(30) | Exposure category |
| internet_exposed_flag | BOOLEAN | Reachable from the internet |
| active_flag | BOOLEAN | Active asset |
| asset_status | VARCHAR(30) | Active / Maintenance / Decommissioned |
| asset_owner | VARCHAR(255) | Owner |
| department_name | VARCHAR(100) | Department |
| location_name | VARCHAR(100) | Location |
| row_hash | CHAR(32) | Change detection |
| effective_start_date, effective_end_date, is_current | DATE / DATE / BOOLEAN | SCD2 columns |

### dim_cvss
One row per distinct CVSS version, vector and score combination.

| Column | Type | Description |
|---|---|---|
| cvss_key (PK) | BIGINT | Surrogate key |
| cvss_version | VARCHAR(5) | 2.0 / 3.0 / 3.1 / 4.0 |
| base_score | NUMERIC(3,1) | 0 to 10 |
| base_severity | VARCHAR(20) | NONE / LOW / MEDIUM / HIGH / CRITICAL |
| attack_vector, attack_complexity, privileges_required, user_interaction, scope | VARCHAR(30) | CVSS base metrics |
| confidentiality_impact, integrity_impact, availability_impact | VARCHAR(30) | CVSS impact metrics |
| vector_string | VARCHAR(255) | Full CVSS vector |

### dim_cwe

| Column | Type | Description |
|---|---|---|
| cwe_key (PK) | BIGINT | Surrogate key |
| cwe_code | VARCHAR(30) | Unique, e.g. CWE-79, NVD-CWE-noinfo |
| cwe_description | VARCHAR(255) | Weakness description |

### dim_kev_status
Junk dimension of CISA KEV flags and required action. Includes a "Not KEV listed" member.

| Column | Type | Description |
|---|---|---|
| kev_status_key (PK) | BIGINT | Surrogate key |
| is_kev_listed | BOOLEAN | In the KEV catalog |
| known_ransomware_use | VARCHAR(20) | Known / Unknown / Not Applicable |
| forensic_triage_required | BOOLEAN | Forensic triage needed |
| required_action | TEXT | Action required by CISA |

### dim_risk_band
Static banding of the 0 to 100 risk priority score.

| Column | Type | Description |
|---|---|---|
| risk_band_key (PK) | BIGINT | Surrogate key |
| risk_band_name | VARCHAR(20) | Critical / High / Medium / Low |
| minimum_score, maximum_score | NUMERIC(6,2) | Inclusive score range |
| priority_rank | SMALLINT | 1 = act first |
| remediation_sla_days | INTEGER | Target days to fix (non-KEV findings) |

---

## Bridge tables

### bridge_cve_product
Many-to-many CVE <-> affected product, with the affected version range from NVD.

| Column | Type | Description |
|---|---|---|
| cve_product_key (PK) | BIGINT | Surrogate key |
| cve_key (FK) | BIGINT | -> dim_cve |
| product_key (FK) | BIGINT | -> dim_product |
| cpe_criteria | TEXT | Full CPE match string |
| cpe_version | VARCHAR(100) | Exact pinned version, NULL when a range is used |
| version_start_including, version_start_excluding | VARCHAR(100) | Range start |
| version_end_including, version_end_excluding | VARCHAR(100) | Range end |
| default_status | VARCHAR(20) | Default 'affected' |
| match_source | VARCHAR(30) | Default 'NVD CPE' |

### bridge_cve_cwe
Primary key (`cve_key`, `cwe_key`), both foreign keys to `dim_cve` and `dim_cwe`.

### bridge_product_software_map
Links installed software to the NVD product it corresponds to (BR-07).

| Column | Type | Description |
|---|---|---|
| product_software_map_key (PK) | BIGINT | Surrogate key |
| product_key (FK) | BIGINT | -> dim_product |
| software_key (FK) | BIGINT | -> dim_software |
| match_method | VARCHAR(50) | Exact Name / Normalized Name / CPE / Manual Mapping |
| match_confidence | VARCHAR(30) | Confirmed / Probable / Manual Review / Unmatched |
| mapping_notes | TEXT | Notes |
| is_active | BOOLEAN | Mapping in use |

---

## Fact tables

All facts carry `batch_id` (the ETL batch that loaded the row) and `loaded_at` (load timestamp).

### fact_vulnerability_intelligence_snapshot
Periodic snapshot. **Grain:** one row per CVE per EPSS snapshot date. Unique on (`assessment_date_key`, `cve_key`).

| Column | Type | Description |
|---|---|---|
| vulnerability_snapshot_key (PK) | BIGINT | Surrogate key |
| assessment_date_key (FK) | INTEGER | EPSS score date -> dim_date |
| published_date_key, last_modified_date_key (FK) | INTEGER | -> dim_date |
| kev_date_added_key, kev_due_date_key (FK) | INTEGER | -> dim_date (-1 when not in KEV) |
| cve_key, cvss_key, kev_status_key, risk_band_key (FK) | BIGINT | -> dim_cve, dim_cvss, dim_kev_status, dim_risk_band |
| epss_score, epss_percentile | NUMERIC(8,6) | 0 to 1 |
| cvss_base_score | NUMERIC(3,1) | 0 to 10 |
| kev_listed_flag, ransomware_use_flag, forensic_triage_flag | SMALLINT | 0/1 |
| days_to_kev_due_date | INTEGER | Negative = overdue, NULL when not in KEV |
| vulnerability_risk_score | NUMERIC(6,2) | 0 to 100: (CVSS/10*35 + EPSS*30 + KEV*20) rescaled from 0-85 |

### fact_asset_software_inventory_snapshot
Periodic snapshot. **Grain:** one row per asset, installed software/version and snapshot date. Unique on (`snapshot_date_key`, `asset_key`, `software_key`).

| Column | Type | Description |
|---|---|---|
| asset_inventory_snapshot_key (PK) | BIGINT | Surrogate key |
| snapshot_date_key (FK) | INTEGER | -> dim_date |
| asset_key (FK) | BIGINT | -> dim_asset |
| software_key (FK) | BIGINT | -> dim_software |
| installed_software_count | INTEGER | Default 1 |
| active_asset_flag, internet_exposed_flag | SMALLINT | 0/1 |
| asset_criticality_score | SMALLINT | 1 to 4 |

### fact_asset_vulnerability_exposure
**Grain:** one row per CVE, affected asset, installed software/version and assessment date. Unique on (`assessment_date_key`, `cve_key`, `asset_key`, `software_key`).

| Column | Type | Description |
|---|---|---|
| asset_vulnerability_exposure_key (PK) | BIGINT | Surrogate key |
| assessment_date_key, remediation_due_date_key, first_detected_date_key (FK) | INTEGER | -> dim_date |
| cve_key, asset_key, software_key, product_key, cvss_key, kev_status_key, risk_band_key (FK) | BIGINT | -> the matching dimensions |
| match_confidence | VARCHAR(30) | Confirmed / Probable / Manual Review / Unmatched |
| version_match_flag | SMALLINT | 1 when the installed version is in the affected range |
| asset_criticality_score | SMALLINT | 1 to 4 |
| internet_exposed_flag, kev_listed_flag | SMALLINT | 0/1 |
| epss_score | NUMERIC(8,6) | 0 to 1 |
| cvss_base_score | NUMERIC(3,1) | 0 to 10 |
| risk_priority_score | NUMERIC(6,2) | 0 to 100: CVSS/10*35 + EPSS*30 + KEV*20 + criticality/4*10 + internet_exposed*5 |
| remediation_status | VARCHAR(30) | Open / In Progress / Mitigated / Closed |
| days_open | INTEGER | Days since first detected, >= 0 |
