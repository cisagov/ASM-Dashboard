# Standard Python Libraries
import json

# Third-Party Libraries
from django.conf import settings
from django.core.management.base import BaseCommand
import redis


class Command(BaseCommand):
    help = "Inspects and displays the most_common_vulnerabilities from AWS ElastiCache (Redis)."

    def handle(self, *args, **options):
        """
        Connects to AWS ElastiCache (Redis), retrieves the 'most_common_vulnerabilities' key,
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
            if redis_client.exists("most_common_vulnerabilities"):
                self.stdout.write(
                    self.style.SUCCESS(
                        "'most_common_vulnerabilities' key exists in Redis."
                    )
                )

                # Retrieve the JSON string
                vulnerabilities_json = redis_client.get("most_common_vulnerabilities")

                if vulnerabilities_json:
                    # Parse the JSON string into Python objects
                    vulnerabilities_data = json.loads(vulnerabilities_json)
                    self.stdout.write("Most Common Vulnerabilities data:")
                    for vuln in vulnerabilities_data:
                        self.stdout.write(
                            f"Title: {vuln.get('title')}, "
                            f"Description: {vuln.get('description')}, "
                            f"Severity: {vuln.get('severity')}, "
                            f"Count: {vuln.get('count')}, "
                            f"Domain: {vuln.get('domain')}"
                        )
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            "'most_common_vulnerabilities' key is empty."
                        )
                    )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        "'most_common_vulnerabilities' key does not exist in Redis."
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
