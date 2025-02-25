"""Infra Ops helpers."""
# File: xfd_api/utils/db_utils.py
# Standard Python Libraries
import os

# Third-Party Libraries
from django.conf import settings
from django.db import connections
import pymysql  # type: ignore


def create_scan_user():
    """Create and configure the XFD scanning user if it does not already exist."""
    # Only create if not in the DMZ
    is_dmz = os.getenv("IS_DMZ", "0") == "1"

    if is_dmz:
        print("IS_DMZ is set to 1. Skipping creation of the scanning user.")
        return

    user = os.getenv("POSTGRES_SCAN_USER")
    password = os.getenv("POSTGRES_SCAN_PASSWORD")
    if not user or not password:
        print("POSTGRES_SCAN_USER or POSTGRES_SCAN_PASSWORD is not set.")
        return

    db_name = settings.DATABASES["default"]["NAME"]

    with connections["default"].cursor() as cursor:
        try:
            # Check if the user already exists
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s;", [user])
            user_exists = cursor.fetchone() is not None

            if not user_exists:
                # Create the user
                cursor.execute(
                    "CREATE ROLE {} LOGIN PASSWORD %s;".format(user), [password]
                )
                print("User '{}' created successfully.".format(user))
            else:
                print("User '{}' already exists. Skipping creation.".format(user))

            # Grant privileges (idempotent as well)
            cursor.execute("GRANT CONNECT ON DATABASE {} TO {};".format(db_name, user))
            cursor.execute("GRANT USAGE ON SCHEMA public TO {};".format(user))
            cursor.execute(
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {};".format(user)
            )
            cursor.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {};".format(
                    user
                )
            )

            print("User '{}' configured successfully.".format(user))
        except Exception as e:
            print("Error creating or configuring scan user: {}".format(e))


def create_matomo_scan_user():
    """Create and configure the Matomo scanning user if it does not already exist."""
    # Only create if not in the DMZ
    is_dmz = os.getenv("IS_DMZ", "0") == "1"
    if is_dmz:
        print("IS_DMZ is set to 1. Skipping creation of the scanning user.")
        return

    # Database connection settings
    db_host = os.getenv("MATOMO_DB_HOST")
    db_name = "matomo"
    db_user = "matomo"
    db_password = os.getenv("MATOMO_DB_PASSWORD")

    scan_user = os.getenv("POSTGRES_SCAN_USER")
    scan_password = os.getenv("POSTGRES_SCAN_PASSWORD")

    if not all([db_host, db_user, db_password, scan_user, scan_password]):
        print("Database connection credentials or scan user details are missing.")
        return

    try:
        conn = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            cursorclass=pymysql.cursors.DictCursor,
        )

        with conn.cursor() as cursor:
            # Check if any record exists for the given username (regardless of host)
            cursor.execute(
                "SELECT User, Host FROM mysql.user WHERE User = %s;", (scan_user,)
            )
            rows = cursor.fetchall()

            # Check if a record exists with host '%'
            user_exists = any(row["Host"] == "%" for row in rows)

            if not user_exists:
                # Create the scan user for host '%'
                # Use the connection's escape() to properly quote values.
                esc_user = conn.escape(scan_user)
                esc_password = conn.escape(scan_password)  # e.g. returns "'password'"
                # Build the SQL manually
                create_user_query = "CREATE USER {}@'%' IDENTIFIED BY {};".format(
                    esc_user, esc_password
                )
                cursor.execute(create_user_query)
                print(
                    "User '{}' created successfully in Matomo database.".format(
                        scan_user
                    )
                )
            else:
                print(
                    "User '{}' already exists in Matomo database. Skipping creation.".format(
                        scan_user
                    )
                )

            # Now grant permissions using the same escaped values.
            esc_user = conn.escape(scan_user)
            grant_queries = [
                "GRANT USAGE ON *.* TO {}@'%';".format(esc_user),
                "GRANT SELECT ON *.* TO {}@'%';".format(esc_user),
                "GRANT PROCESS, REPLICATION CLIENT ON *.* TO {}@'%';".format(esc_user),
                "GRANT SHOW DATABASES ON *.* TO {}@'%';".format(esc_user),
                "GRANT SHOW VIEW ON *.* TO {}@'%';".format(esc_user),
            ]
            for query in grant_queries:
                cursor.execute(query)
            cursor.execute("FLUSH PRIVILEGES;")

            # Query the grants for the user.
            # Construct the user identifier exactly as stored.
            show_grants_query = "SHOW GRANTS FOR {}@'%';".format(esc_user)
            cursor.execute(show_grants_query)
            grants = cursor.fetchall()

            # Print the grants to verify the user's permissions
            for grant in grants:
                print(grant)

            print(
                "User '{}' configured successfully in Matomo database.".format(esc_user)
            )

        conn.commit()
        conn.close()

    except Exception as e:
        print(
            "Error creating or configuring scan user for Matomo database: {}".format(e)
        )
