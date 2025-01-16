-- Create the user (role)
CREATE USER mdl_local WITH PASSWORD 'mini_data_lake';

SELECT CURRENT_USER;

-- Optionally grant privileges on a specific database (if required)
CREATE DATABASE mini_data_lake_local;
GRANT ALL PRIVILEGES ON DATABASE mini_data_lake_local TO mdl_local;
ALTER SCHEMA public OWNER TO mdl_local;
ALTER DATABASE mini_data_lake_local OWNER TO mdl_local;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

SET ROLE mdl_local;
