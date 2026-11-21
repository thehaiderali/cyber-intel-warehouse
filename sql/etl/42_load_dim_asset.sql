/*
   42_load_dim_asset.sql
   stg_asset -> dim_asset (SCD Type 2)

   Business key  asset_id  ->  surrogate key asset_key (starts at 1001)

   For every asset in the batch a row_hash (md5 of all descriptive columns) is
   compared with the current dim_asset row:
     new asset_id             insert a new current row
     same hash                nothing to do
     different hash           close the current row (effective_end_date = batch_date - 1,
                              is_current = FALSE) and insert a new current row
     changed twice in a day   the row opened today is updated in place
   Assets that are not in this batch keep their current row.
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.asset_src;
CREATE TEMP TABLE asset_src AS
SELECT s.*,
       md5(concat_ws('|', s.hostname, s.ip_address, s.asset_type, s.os_name, s.os_version, s.environment,
                     s.criticality_level, s.asset_criticality_score, s.exposure_level, s.internet_exposed_flag,
                     s.active_flag, s.asset_status, s.asset_owner, s.department_name, s.location_name)) AS row_hash
FROM stg_asset s;

-- changed today already: overwrite the row opened today
UPDATE dim_asset d
SET hostname = s.hostname, ip_address = s.ip_address, asset_type = s.asset_type, os_name = s.os_name,
    os_version = s.os_version, environment = s.environment, criticality_level = s.criticality_level,
    asset_criticality_score = s.asset_criticality_score, exposure_level = s.exposure_level,
    internet_exposed_flag = s.internet_exposed_flag, active_flag = s.active_flag, asset_status = s.asset_status,
    asset_owner = s.asset_owner, department_name = s.department_name, location_name = s.location_name,
    row_hash = s.row_hash
FROM asset_src s
WHERE d.asset_id = s.asset_id AND d.is_current
  AND d.effective_start_date = :'batch_date'::DATE
  AND d.row_hash <> s.row_hash;

-- changed: close the current version
DROP TABLE IF EXISTS pg_temp.asset_changed;
CREATE TEMP TABLE asset_changed AS
SELECT d.asset_key, d.asset_id
FROM dim_asset d
JOIN asset_src s ON s.asset_id = d.asset_id
WHERE d.is_current AND d.row_hash <> s.row_hash
  AND d.effective_start_date < :'batch_date'::DATE;

UPDATE dim_asset d
SET is_current = FALSE, effective_end_date = :'batch_date'::DATE - 1
FROM asset_changed c
WHERE d.asset_key = c.asset_key;

-- new assets and new versions of changed assets
INSERT INTO dim_asset (asset_id, hostname, ip_address, asset_type, os_name, os_version, environment, criticality_level,
                       asset_criticality_score, exposure_level, internet_exposed_flag, active_flag, asset_status,
                       asset_owner, department_name, location_name, row_hash, effective_start_date)
SELECT s.asset_id, s.hostname, s.ip_address, s.asset_type, s.os_name, s.os_version, s.environment, s.criticality_level,
       s.asset_criticality_score, s.exposure_level, s.internet_exposed_flag, s.active_flag, s.asset_status,
       s.asset_owner, s.department_name, s.location_name, s.row_hash, :'batch_date'::DATE
FROM asset_src s
WHERE NOT EXISTS (SELECT 1 FROM dim_asset d WHERE d.asset_id = s.asset_id AND d.is_current)
ORDER BY s.asset_id;

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'dimension', 'Load dim_asset (SCD2)', 'dim_asset',
       (SELECT count(*) FROM asset_src),
       (SELECT count(*) FROM dim_asset WHERE effective_start_date = :'batch_date'::DATE AND asset_key > 0),
       format('new versions for changed assets %s; current assets %s',
              (SELECT count(*) FROM asset_changed),
              (SELECT count(*) FROM dim_asset WHERE is_current AND asset_key > 0))
WHERE EXISTS (SELECT 1 FROM asset_src);

DROP TABLE asset_src, asset_changed;
