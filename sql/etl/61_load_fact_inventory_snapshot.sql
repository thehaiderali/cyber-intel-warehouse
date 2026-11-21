/*
   61_load_fact_inventory_snapshot.sql
   Periodic snapshot: one row per asset, installed software/version and batch date.

   Business key -> surrogate key lookups
     asset_id                          -> dim_asset.asset_key (current version)
     software name + software version  -> dim_software.software_key

   Batches with an inventory file use it. Batches without one (all incremental
   batches) carry the previous snapshot forward, re-pointed at the current
   asset versions, so every date has a complete inventory.
*/

SET search_path = project_dw, project_staging;

DROP TABLE IF EXISTS pg_temp.inventory_src;
CREATE TEMP TABLE inventory_src AS
SELECT a.asset_key, sw.software_key, a.active_flag, a.internet_exposed_flag, a.asset_criticality_score
FROM stg_asset s
JOIN dim_asset    a  ON a.asset_id = s.asset_id AND a.is_current
JOIN dim_software sw ON sw.normalized_software_name = lower(s.software_name) AND sw.software_version = s.software_version;

INSERT INTO inventory_src
SELECT cur.asset_key, f.software_key, cur.active_flag, cur.internet_exposed_flag, cur.asset_criticality_score
FROM fact_asset_software_inventory_snapshot f
JOIN dim_asset prev ON prev.asset_key = f.asset_key
JOIN dim_asset cur  ON cur.asset_id = prev.asset_id AND cur.is_current
WHERE NOT EXISTS (SELECT 1 FROM stg_asset)
  AND f.snapshot_date_key = (SELECT max(snapshot_date_key) FROM fact_asset_software_inventory_snapshot
                             WHERE snapshot_date_key < fn_date_key(:'batch_date'::DATE));

INSERT INTO fact_asset_software_inventory_snapshot
    (snapshot_date_key, asset_key, software_key, installed_software_count, active_asset_flag,
     internet_exposed_flag, asset_criticality_score, batch_id)
SELECT fn_date_key(:'batch_date'::DATE), asset_key, software_key, 1,
       active_flag::INT, internet_exposed_flag::INT, asset_criticality_score, :'batch_id'
FROM inventory_src
ON CONFLICT (snapshot_date_key, asset_key, software_key) DO UPDATE
    SET active_asset_flag = EXCLUDED.active_asset_flag,
        internet_exposed_flag = EXCLUDED.internet_exposed_flag,
        asset_criticality_score = EXCLUDED.asset_criticality_score,
        batch_id = EXCLUDED.batch_id,
        loaded_at = clock_timestamp();

INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out, message)
SELECT :'batch_id', 'fact', 'Load fact_asset_software_inventory_snapshot', 'fact_asset_software_inventory_snapshot',
       (SELECT count(*) FROM inventory_src),
       (SELECT count(*) FROM fact_asset_software_inventory_snapshot WHERE snapshot_date_key = fn_date_key(:'batch_date'::DATE)),
       CASE WHEN EXISTS (SELECT 1 FROM stg_asset) THEN 'from this batch''s inventory file'
            ELSE 'carried forward from the previous snapshot' END;

DROP TABLE inventory_src;
