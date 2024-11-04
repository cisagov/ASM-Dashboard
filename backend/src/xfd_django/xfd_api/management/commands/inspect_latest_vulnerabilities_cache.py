# Standard Python Libraries
import json

# Third-Party Libraries
from django.conf import settings
from django.core.management.base import BaseCommand
import redis


class Command(BaseCommand):
    help = (
        "Inspects and displays the latest_vulnerabilities from AWS ElastiCache (Redis)."
    )

    def handle(self, *args, **options):
        """
        Connects to AWS ElastiCache (Redis), retrieves the 'latest_vulnerabilities' key,
        and displays its contents.
        """

        try:
            # Initialize Redis client
            redis_client = redis.StrictRedis(
                host=settings.ELASTICACHE_ENDPOINT,
                port=6379,
                db=0,
                decode_responses=True,  # Automatically decode responses as UTF-8 strings
            )

            # Check if the key exists
            if redis_client.exists("latest_vulnerabilities"):
                self.stdout.write(
                    self.style.SUCCESS("'latest_vulnerabilities' key exists in Redis.")
                )

                # Retrieve the JSON string
                vulnerabilities_json = redis_client.get("latest_vulnerabilities")

                if vulnerabilities_json:
                    # Parse the JSON string into Python objects
                    vulnerabilities_data = json.loads(vulnerabilities_json)
                    self.stdout.write("Vulnerabilities data:")
                    for vuln in vulnerabilities_data:
                        self.stdout.write(
                            f"ID: {vuln['id']}, Title: {vuln['title']}, "
                            f"State: {vuln['state']}, CreatedAt: {vuln['createdAt']}, "
                            f"Domain: {vuln['domain']}"
                        )
                else:
                    self.stdout.write(
                        self.style.WARNING("'latest_vulnerabilities' key is empty.")
                    )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        "'latest_vulnerabilities' key does not exist in Redis."
                    )
                )

        except redis.ConnectionError as conn_err:
            self.stderr.write(self.style.ERROR(f"Redis connection error: {conn_err}"))
        except redis.RedisError as redis_err:
            self.stderr.write(self.style.ERROR(f"Redis error: {redis_err}"))
        except json.JSONDecodeError as json_err:
            self.stderr.write(self.style.ERROR(f"JSON decode error: {json_err}"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"An unexpected error occurred: {e}"))
