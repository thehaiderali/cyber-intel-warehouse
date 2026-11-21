/*
   04_functions.sql
   Helper functions used by the ETL scripts (schema project_staging).

   fn_clean_text          trim, collapse inner whitespace, turn placeholders into NULL
   fn_version_compare     compare two software version strings (-1 / 0 / 1)
   fn_version_in_range    is an installed version affected by an NVD CPE match?
   fn_date_key            DATE -> dim_date key (YYYYMMDD, -1 when unknown)
   fn_cve_risk_score      CVE-level risk score (0-100)
   fn_exposure_risk_score asset exposure risk score (0-100), Phase 1 formula

   Run: psql -U postgres -d intel_dw -f sql/04_functions.sql
*/

SET client_min_messages = warning;
SET search_path = project_staging;

-- ' lahore  dc ' -> 'lahore dc', '' / 'N/A' / 'null' / '-' -> NULL
CREATE OR REPLACE FUNCTION fn_clean_text(p_value TEXT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
             WHEN p_value IS NULL THEN NULL
             WHEN lower(btrim(p_value)) IN ('', 'n/a', 'na', 'null', 'none', '-', 'unknown') THEN NULL
             ELSE regexp_replace(btrim(p_value), '\s+', ' ', 'g')
           END;
$$;

-- Versions are compared piece by piece after splitting on . - _ + : ~ and spaces.
-- Each piece is compared by its leading number first, then by the remaining
-- text, so '2.4.9' < '2.4.49', '9.6' < '9.6p1', '1.0-rc1' < '1.0'.
-- A missing piece counts as '0' ('8.0' = '8.0.0'). BR-04: versions stay text.
CREATE OR REPLACE FUNCTION fn_version_compare(p_a TEXT, p_b TEXT)
RETURNS INTEGER
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    v_a      TEXT[] := regexp_split_to_array(lower(btrim(p_a)), '[.\-_+:~ ]+');
    v_b      TEXT[] := regexp_split_to_array(lower(btrim(p_b)), '[.\-_+:~ ]+');
    v_x      TEXT;
    v_y      TEXT;
    v_xn     NUMERIC;
    v_yn     NUMERIC;
    v_xs     TEXT;
    v_ys     TEXT;
BEGIN
    FOR i IN 1 .. greatest(cardinality(v_a), cardinality(v_b)) LOOP
        v_x := coalesce(nullif(v_a[i], ''), '0');
        v_y := coalesce(nullif(v_b[i], ''), '0');
        CONTINUE WHEN v_x = v_y;

        v_xn := coalesce(substring(v_x FROM '^[0-9]+')::NUMERIC, -1);  -- text-only piece sorts before numbers
        v_yn := coalesce(substring(v_y FROM '^[0-9]+')::NUMERIC, -1);
        IF v_xn <> v_yn THEN
            RETURN CASE WHEN v_xn < v_yn THEN -1 ELSE 1 END;
        END IF;

        v_xs := substring(v_x FROM '^[0-9]*(.*)$');
        v_ys := substring(v_y FROM '^[0-9]*(.*)$');
        IF v_xs <> v_ys THEN                                -- same number: '6' < '6p1' < '6p2'
            RETURN CASE WHEN v_xs < v_ys THEN -1 ELSE 1 END;
        END IF;
    END LOOP;
    RETURN 0;
END;
$$;

-- TRUE  : the installed version is affected (exact pin or inside the range)
-- FALSE : not affected
-- NULL  : NVD gives no version information (all versions); caller decides
CREATE OR REPLACE FUNCTION fn_version_in_range(
    p_installed          TEXT,
    p_exact              TEXT,
    p_start_including    TEXT,
    p_start_excluding    TEXT,
    p_end_including      TEXT,
    p_end_excluding      TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF p_installed IS NULL THEN
        RETURN NULL;
    END IF;
    IF p_exact IS NOT NULL THEN
        RETURN fn_version_compare(p_installed, p_exact) = 0;
    END IF;
    IF p_start_including IS NULL AND p_start_excluding IS NULL
       AND p_end_including IS NULL AND p_end_excluding IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN (p_start_including IS NULL OR fn_version_compare(p_installed, p_start_including) >= 0)
       AND (p_start_excluding IS NULL OR fn_version_compare(p_installed, p_start_excluding) >  0)
       AND (p_end_including   IS NULL OR fn_version_compare(p_installed, p_end_including)   <= 0)
       AND (p_end_excluding   IS NULL OR fn_version_compare(p_installed, p_end_excluding)   <  0);
END;
$$;

-- dim_date covers 1985-01-01 .. 2035-12-31 (see 10_seed_reference_data.sql).
CREATE OR REPLACE FUNCTION fn_date_key(p_date DATE)
RETURNS INTEGER
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
             WHEN p_date BETWEEN DATE '1985-01-01' AND DATE '2035-12-31'
             THEN to_char(p_date, 'YYYYMMDD')::INTEGER
             ELSE -1
           END;
$$;

-- CVE-level risk: the CVE components of the Phase 1 formula
-- (CVSS/10*35 + EPSS*30 + KEV*20, max 85) rescaled to 0-100.
-- Missing CVSS / EPSS count as 0.
CREATE OR REPLACE FUNCTION fn_cve_risk_score(p_cvss NUMERIC, p_epss NUMERIC, p_kev_flag INTEGER)
RETURNS NUMERIC(6,2)
LANGUAGE sql IMMUTABLE AS $$
    SELECT round((coalesce(p_cvss, 0) / 10 * 35
                + coalesce(p_epss, 0) * 30
                + coalesce(p_kev_flag, 0) * 20) * 100 / 85, 2);
$$;

-- Phase 1 risk priority formula (Grain Definition Document):
-- CVSS/10*35 + EPSS*30 + KEV*20 + criticality/4*10 + internet_exposed*5  (0-100)
CREATE OR REPLACE FUNCTION fn_exposure_risk_score(
    p_cvss NUMERIC, p_epss NUMERIC, p_kev_flag INTEGER, p_criticality INTEGER, p_internet_exposed INTEGER)
RETURNS NUMERIC(6,2)
LANGUAGE sql IMMUTABLE AS $$
    SELECT round(coalesce(p_cvss, 0) / 10 * 35
               + coalesce(p_epss, 0) * 30
               + coalesce(p_kev_flag, 0) * 20
               + coalesce(p_criticality, 0)::NUMERIC / 4 * 10
               + coalesce(p_internet_exposed, 0) * 5, 2);
$$;
