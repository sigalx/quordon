USE application;
CREATE TABLE routing_marker (
  id BIGINT NOT NULL PRIMARY KEY,
  contour VARCHAR(16) NOT NULL,
  hidden_value VARCHAR(16) NOT NULL
) ENGINE=InnoDB;
INSERT INTO routing_marker VALUES (1, 'test', 'hidden');
