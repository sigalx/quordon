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
GRANT BACKUP_ADMIN ON *.* TO 'quordon'@'%';
