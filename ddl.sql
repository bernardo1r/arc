CREATE TABLE metadata(
	id INTEGER PRIMARY KEY CHECK(typeof(id) = "integer"),
	name TEXT NOT NULL UNIQUE CHECK(typeof(name) = "text"),
	size INTEGER NOT NULL CHECK(typeof(size) = "integer"),
	blocks INTEGER NOT NULL CHECK(typeof(blocks) = "integer"),
	mod_time INTEGER NOT NULL CHECK(typeof(mod_time) = "integer"),
	compressed INTEGER NOT NULL CHECK(compressed IN (0, 1)),
	encrypted INTEGER NOT NULL CHECK(encrypted IN (0, 1))
);

CREATE TABLE data(
	id INTEGER CHECK(typeof(id) = "integer"),
	block_id INTEGER CHECK(typeof(block_id) = "integer"),
	data BLOB NOT NULL CHECK(typeof(data) = "blob"),
	FOREIGN KEY (id) REFERENCES metadata(id) ON DELETE CASCADE,
	PRIMARY KEY (id, block_id)
);

CREATE TABLE encryption_metadata(
	id INTEGER PRIMARY KEY CHECK(typeof(id) = "integer"),
	key BLOB UNIQUE NOT NULL CHECK(typeof(key) = "blob"),
	FOREIGN KEY (id) REFERENCES metadata(id) ON DELETE CASCADE
);

CREATE TABLE encryption_key_params(
	params BLOB PRIMARY KEY CHECK(typeof(params) = "blob")
);