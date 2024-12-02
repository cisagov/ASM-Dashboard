.PHONY: syncdb

# Synchronize and populate the database
syncdb:
	docker compose exec backend python manage.py syncdb

pytest:
	docker compose exec backend python manage.py makemigrations
	docker compose exec backend pytest --no-migrations --reuse-db $(FILE)