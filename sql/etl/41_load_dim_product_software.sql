/*
   41_load_dim_product_software.sql
   dim_product   vendor/product pairs found in NVD CPE matches (stg_cve_cpe)
   dim_software  software name + version pairs found in the asset inventory (stg_asset)

   Both are Type 1 dimensions keyed by a surrogate key; the natural key is
   vendor:product for products and (normalised name, version) for software.
*/

SET search_path = project_dw, project_staging;


-- dim_product

WITH src AS (
    SELECT DISTINCT ON (cpe_vendor, cpe_product) cpe_vendor, cpe_product, cpe_part
    FROM stg_cve_cpe
    ORDER BY cpe_vendor, cpe_product, cpe_part
),
ins AS (
    INSERT INTO dim_product (vendor_name, product_name, vendor_product_name, source_vendor_name, source_product_name,
                             cpe_part, normalization_status)
    SELECT s.cpe_vendor,
           s.cpe_product,
           s.cpe_vendor || ':' || s.cpe_product,
           initcap(replace(s.cpe_vendor, '_', ' ')),
           initcap(replace(s.cpe_product, '_', ' ')),
           s.cpe_part,
           'CPE'
    FROM src s
    ON CONFLICT (vendor_product_name) DO NOTHING
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'dimension', 'Load dim_product', 'dim_product', (SELECT count(*) FROM src), (SELECT count(*) FROM ins);


-- dim_software

WITH src AS (
    SELECT DISTINCT a.software_name, a.software_version
    FROM stg_asset a
),
ins AS (
    INSERT INTO dim_software (software_name, software_vendor, software_version, normalized_software_name,
                              normalized_vendor_name, normalization_status)
    SELECT s.software_name,
           m.software_vendor,
           s.software_version,
           lower(s.software_name),
           lower(m.software_vendor),
           CASE WHEN m.software_name IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END
    FROM src s
    LEFT JOIN LATERAL (SELECT software_name, software_vendor FROM ref_software_product_map r
                       WHERE r.software_name = s.software_name LIMIT 1) m ON TRUE
    ON CONFLICT (normalized_software_name, software_version) DO NOTHING
    RETURNING 1
)
INSERT INTO etl_step_log (batch_id, layer, step_name, target_table, rows_in, rows_out)
SELECT :'batch_id', 'dimension', 'Load dim_software', 'dim_software', (SELECT count(*) FROM src), (SELECT count(*) FROM ins);
