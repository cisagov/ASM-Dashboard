.PHONY: syncdb

# Synchronize and populate the database
syncdb:
	docker compose exec backend python manage.py syncdb
