USE application;
CREATE TABLE routing_marker (
  id BIGINT NOT NULL PRIMARY KEY,
  contour VARCHAR(16) NOT NULL,
  hidden_value VARCHAR(16) NOT NULL
) ENGINE=InnoDB;
INSERT INTO routing_marker VALUES (1, 'rc', 'hidden');

-- The extra numeric row makes histogram routing observable independently of
-- the datasource string in the API envelope.
INSERT INTO numeric_distribution VALUES
  (12, -900, 100, 100, 1.5, 1.5, '1.5', 'all', '2026-09-18 10:00:00', 'small', 7);
ANALYZE TABLE numeric_distribution;
