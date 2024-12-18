.PHONY: syncdb
.PHONY: populate-cache

# Synchronize and populate the database
syncdb:
	docker compose exec backend python manage.py syncdb

syncdb-populate:
	docker compose exec backend python manage.py syncdb --populate

# Pytest
pytest:
	docker compose exec backend python manage.py makemigrations
	docker compose exec backend pytest --no-migrations --reuse-db $(FILE)

# Redis lambdas
populate-cache:
	docker compose exec backend python manage.py populate_services_cache
	docker compose exec backend python manage.py populate_ports_cache
	docker compose exec backend python manage.py populate_vulns_cache
	docker compose exec backend python manage.py populate_most_common_vulns_cache
	docker compose exec backend python manage.py populate_latest_vulns_cache
	docker compose exec backend python manage.py populate_severity_count_cache
	docker compose exec backend python manage.py populate_by_orgs_cache
