-- The init client must interpret synthetic non-ASCII SQL literals as UTF-8.
SET NAMES utf8mb4;

CREATE TABLE application.orders (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status VARCHAR(32) NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    created_at DATETIME NOT NULL,
	legacy_text VARCHAR(32) CHARACTER SET latin1 NOT NULL,
    payload LONGTEXT NOT NULL,
    location POINT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_orders_status (status),
	KEY idx_orders_created_at (created_at),
    KEY idx_orders_invisible (status) INVISIBLE
);

INSERT INTO application.orders (status, amount, created_at, legacy_text, payload, location) VALUES
    ('active', 10.00, '2026-08-15 10:00:00', _latin1 0x636166E9, 'small', ST_GeomFromText('POINT(1 2)')),
    ('closed', 20.00, '2026-08-15 11:00:00', _latin1 0x6665726DE9, REPEAT(CHAR(0), 1100000), ST_GeomFromText('POINT(3 4)'));

CREATE TABLE application.temporal_events (
    id BIGINT UNSIGNED NOT NULL,
    event_date DATE NOT NULL,
    wall_time DATETIME(6) NOT NULL,
    occurred_at TIMESTAMP(6) NOT NULL,
    token BINARY(2) NOT NULL,
    label VARCHAR(32) NOT NULL,
    PRIMARY KEY (event_date, id),
    UNIQUE KEY idx_temporal_wall (wall_time, id),
    UNIQUE KEY idx_temporal_occurred (occurred_at, token)
) ENGINE=InnoDB;

INSERT INTO application.temporal_events (id, event_date, wall_time, occurred_at, token, label) VALUES
    (1, '2026-09-14', '2026-09-14 10:00:00.000001', '2026-09-14 07:00:00.000001', 0x0001, 'first'),
    (2, '2026-09-15', '2026-09-15 12:34:56.123455', '2026-09-15 09:34:56.123455', 0x0002, 'second'),
    (3, '2026-09-15', '2026-09-15 12:34:56.123456', '2026-09-15 09:34:56.123456', 0x0003, 'third');

-- Synthetic fixtures: charset conversion, native collation equality, trailing
-- spaces, fixed-width keys, supplementary characters and numeric tie-breakers.
CREATE TABLE application.character_keys (
    id INT NOT NULL,
    unicode_label VARCHAR(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
    western_label VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_german2_ci NOT NULL,
    cyrillic_label VARCHAR(32) CHARACTER SET cp1251 COLLATE cp1251_general_ci NOT NULL,
    wide_label VARCHAR(32) CHARACTER SET utf16 COLLATE utf16_unicode_ci NOT NULL,
    ascii_label CHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    hidden_value VARCHAR(32) NOT NULL,
    PRIMARY KEY (unicode_label, western_label, id),
    UNIQUE KEY idx_character_western (western_label, id),
    UNIQUE KEY idx_character_cyrillic (cyrillic_label, id),
    UNIQUE KEY idx_character_wide (wide_label, id),
    UNIQUE KEY idx_character_ascii (ascii_label, id)
) ENGINE=InnoDB;

INSERT INTO application.character_keys VALUES
    (0, '', '', '', '', '', 'hidden'),
    (1, 'a', 'Straße', 'А', _utf8mb4 0xF09F9880, 'a', 'hidden'),
    (2, 'A', 'Strasse', 'а', _utf8mb4 0xF09F9880, 'a', 'hidden'),
    (3, 'á', 'Strasse ', 'Б', _utf8mb4 0xF09F9881, 'b', 'hidden');

-- CP932 has duplicate byte encodings for U+2160. The IBM extension encoding
-- below converts to Unicode but converts back to the canonical NEC encoding.
CREATE TABLE application.lossy_character_keys (
    label VARCHAR(8) CHARACTER SET cp932 COLLATE cp932_bin NOT NULL,
    id INT NOT NULL,
    PRIMARY KEY (label, id)
) ENGINE=InnoDB;
INSERT INTO application.lossy_character_keys VALUES
    ('A', 1), (CONVERT(0xFA4A USING cp932), 2);

-- Policy-hidden tables make the unfiltered metadata larger than the dedicated
-- metadata-reader profile budget. They must not affect its filtered response.
CREATE TABLE application.hidden_metadata_padding_000000000000000000000000000001 (id BIGINT NOT NULL);
CREATE TABLE application.hidden_metadata_padding_000000000000000000000000000002 (id BIGINT NOT NULL);
CREATE TABLE application.hidden_metadata_padding_000000000000000000000000000003 (id BIGINT NOT NULL);
CREATE TABLE application.hidden_metadata_padding_000000000000000000000000000004 (id BIGINT NOT NULL);

-- On Linux MySQL defaults to lower_case_table_names=0, so this view can
-- coexist with the lower-case base table and exercises exact-case gating.
CREATE SQL SECURITY DEFINER VIEW application.Orders AS
SELECT id, status, amount AS view_only FROM application.orders;

CREATE TABLE application.partitioned_orders (
    id BIGINT UNSIGNED NOT NULL,
    status VARCHAR(32) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB
PARTITION BY RANGE (id) (
    PARTITION p_low VALUES LESS THAN (100),
    PARTITION p_max VALUES LESS THAN MAXVALUE
);

CREATE TABLE application.subpartitioned_events (
    id BIGINT UNSIGNED NOT NULL,
    created_year INT NOT NULL,
    PRIMARY KEY (id, created_year)
) ENGINE=InnoDB
PARTITION BY RANGE (created_year)
SUBPARTITION BY HASH (id)
SUBPARTITIONS 2 (
    PARTITION p_2025 VALUES LESS THAN (2026),
    PARTITION p_max VALUES LESS THAN MAXVALUE
);

CREATE TABLE application.legacy_exact_rows (
    id BIGINT UNSIGNED NOT NULL PRIMARY KEY
) ENGINE=MyISAM;

CREATE USER 'quordon'@'%' IDENTIFIED BY 'quordon-password';
GRANT SELECT ON application.* TO 'quordon'@'%';

CREATE SQL SECURITY DEFINER VIEW application.join_orders AS
SELECT o.id AS order_id, t.id AS event_id, o.status, o.amount
FROM application.orders o JOIN application.temporal_events t ON t.id = o.id;

CREATE ALGORITHM=TEMPTABLE SQL SECURITY DEFINER VIEW application.materialized_orders AS
SELECT id, status, amount FROM application.orders;

-- Only synthetic values: a deny on the underlying field does not propagate
-- through an administrator-owned alias. The direct view field is denied.
CREATE SQL SECURITY DEFINER VIEW application.character_aliases AS
SELECT id, unicode_label, hidden_value, hidden_value AS exposed_alias
FROM application.character_keys;

-- Independent selective indexes make native union/intersect/sort_union plans
-- cheaper than scanning the padded rows, without optimizer or index hints.
CREATE TABLE application.merge_rows (
    id INT NOT NULL PRIMARY KEY,
    a INT NOT NULL,
    b INT NOT NULL,
    pad VARCHAR(512) NOT NULL,
    KEY idx_a (a),
    KEY idx_b (b)
) ENGINE=InnoDB;
SET SESSION cte_max_recursion_depth=10001;
INSERT INTO application.merge_rows
WITH RECURSIVE seq AS (
    SELECT 0 AS n
    UNION ALL SELECT n + 1 FROM seq WHERE n < 9999
)
SELECT n + 1, MOD(n, 100), FLOOR(n / 100), REPEAT('x', 512) FROM seq;
ANALYZE TABLE application.merge_rows;

-- This is one quoted index name. Neither idx_a nor idx_b exists on the table.
CREATE TABLE application.comma_rows (
    id INT NOT NULL PRIMARY KEY,
    a INT NOT NULL,
    pad VARCHAR(512) NOT NULL,
    KEY `idx_a,idx_b` (a)
) ENGINE=InnoDB;
INSERT INTO application.comma_rows
SELECT id, a, pad FROM application.merge_rows WHERE id <= 1000;
ANALYZE TABLE application.comma_rows;

-- In a merge, the comma in this native name is not escaped in JSON key.
-- key_length still reports exactly two participating physical indexes.
CREATE TABLE application.ambiguous_merge_rows (
    id INT NOT NULL PRIMARY KEY,
    a INT NOT NULL,
    b INT NOT NULL,
    pad VARCHAR(512) NOT NULL,
    KEY `idx_a,idx_b` (a),
    KEY idx_c (b)
) ENGINE=InnoDB;
INSERT INTO application.ambiguous_merge_rows SELECT * FROM application.merge_rows;
ANALYZE TABLE application.ambiguous_merge_rows;

CREATE ALGORITHM=MERGE SQL SECURITY DEFINER VIEW application.physical_alias_view AS
SELECT `<orders>`.id, `<orders>`.a, `<orders>`.b
FROM application.ambiguous_merge_rows AS `<orders>`;

-- Keep invalid historic temporal values isolated from the ordinary regressions.
-- Only the fixture administrator relaxes its own session for data creation.
SET @diagnostic_original_sql_mode = @@SESSION.sql_mode;
SET @diagnostic_original_time_zone = @@SESSION.time_zone;
SET SESSION sql_mode = 'ALLOW_INVALID_DATES';
SET SESSION time_zone = '+00:00';
CREATE TABLE application.diagnostic_dates (
    id BIGINT NOT NULL PRIMARY KEY,
    event_date DATE NOT NULL,
    wall_time DATETIME(6) NOT NULL,
    occurred_at TIMESTAMP(6) NOT NULL,
    optional_date DATE NULL,
    hidden_date DATE NOT NULL,
    UNIQUE KEY idx_diagnostic_date (event_date, id),
    UNIQUE KEY idx_diagnostic_wall_time (wall_time, id)
) ENGINE=InnoDB;
INSERT INTO application.diagnostic_dates VALUES
    (1, '0000-00-00', '0000-00-00 00:00:00.000000', '0000-00-00 00:00:00.000000', NULL, '2026-01-01'),
    (2, '0001-01-01', '0001-01-01 00:00:00.000001', '2026-01-01 00:00:00.000001', '0000-00-00', '2026-01-01'),
    (3, '0999-12-31', '0999-12-31 23:59:59.123456', '2026-01-01 00:00:00.000002', '2026-00-01', '2026-01-01'),
    (4, '1000-01-01', '1000-01-01 00:00:00.000000', '2026-01-01 00:00:00.000003', '2026-02-31', '2026-01-01'),
    (5, '2026-00-01', '2026-00-01 01:02:03.000000', '2026-01-01 00:00:00.000004', '0001-01-01', '2026-01-01'),
    (6, '2026-02-31', '2026-02-31 01:02:03.123456', '2026-01-01 00:00:00.000005', '0999-12-31', '2026-01-01'),
    (7, '2026-02-31', '2026-02-31 01:02:03.123456', '2026-01-01 00:00:00.000006', '9999-12-31', '2026-01-01'),
    (8, '9999-12-31', '9999-12-31 23:59:59.499999', '2026-01-01 00:00:00.000007', '2026-01-01', '2026-01-01');
SET SESSION sql_mode = @diagnostic_original_sql_mode;
SET SESSION time_zone = @diagnostic_original_time_zone;
ANALYZE TABLE application.diagnostic_dates;
CREATE ALGORITHM=MERGE SQL SECURITY DEFINER VIEW application.diagnostic_slow_dates AS
SELECT CASE WHEN SLEEP(5) = 0 THEN event_date ELSE NULL END AS event_date
FROM application.diagnostic_dates WHERE id = 2;

-- Exact fixed numeric bucket fixtures; reader grants remain SELECT-only.
CREATE TABLE application.numeric_distribution (
 id INT NOT NULL PRIMARY KEY,
 signed_value BIGINT NULL,
 unsigned_value BIGINT UNSIGNED NULL,
 decimal_value DECIMAL(65,30) NULL,
 float_value FLOAT NULL,
 double_value DOUBLE NULL,
 text_value VARCHAR(32) NULL,
 category VARCHAR(16) NOT NULL,
 occurred_at DATETIME NOT NULL,
 payload TEXT NOT NULL,
 hidden_value INT NOT NULL
) ENGINE=InnoDB;
INSERT INTO application.numeric_distribution VALUES (1, NULL, NULL, NULL, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', 'small', 7);
INSERT INTO application.numeric_distribution VALUES (2, -9223372036854775808, 0, -123.500000000000000000000000000001, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', 'small', 7);
INSERT INTO application.numeric_distribution VALUES (3, -2, 1, -123.5, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (4, -1, 2, -0.000000000000000000000000000001, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (5, 0, 9007199254740992, 0, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (6, 1, 9007199254740993, 0.000000000000000000000000000001, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (7, 2, 9007199254740994, 1.499999999999999999999999999999, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (8, 9007199254740992, 18446744073709551614, 1.5, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (9, 9007199254740993, 18446744073709551615, 9007199254740992.999999999999999999999999999999, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (10, 9007199254740994, 18446744073709551615, 9007199254740993, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);
INSERT INTO application.numeric_distribution VALUES (11, 9223372036854775807, 18446744073709551615, 99999999999999999999999999999999999.999999999999999999999999999999, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', REPEAT('x',5000), 7);

ANALYZE TABLE application.numeric_distribution;
