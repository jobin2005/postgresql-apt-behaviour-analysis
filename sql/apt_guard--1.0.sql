-- apt_guard extension schema
CREATE OR REPLACE FUNCTION apt_guard_version() RETURNS text
AS 'MODULE_PATHNAME', 'apt_guard_version'
LANGUAGE C STRICT;
