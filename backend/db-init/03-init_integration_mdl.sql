
-- Optionally grant privileges on a specific database (if required)
CREATE DATABASE mini_data_lake_integration_local;
GRANT ALL PRIVILEGES ON DATABASE mini_data_lake_integration_local TO dmz_mdl;
ALTER SCHEMA public OWNER TO dmz_mdl;
ALTER DATABASE mini_data_lake_integration_local OWNER TO dmz_mdl;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

SET ROLE dmz_mdl;
