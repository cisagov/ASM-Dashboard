from django.core.management.base import BaseCommand
from django.conf import settings
import redis
import json



class Command(BaseCommand):
    help = 'Inspects and displays the num_vulnerabilities_stats from AWS ElastiCache (Redis).'

    def handle(self, *args, **options):
        """
        Connects to AWS ElastiCache (Redis), retrieves the 'num_vulnerabilities_stats' hash,
        and displays its contents.
        """


        try:
            # Initialize Redis client
            redis_client = redis.StrictRedis(
                host=settings.ELASTICACHE_ENDPOINT,
                port=6379,
                db=0,
                decode_responses=True
                # Automatically decode responses as UTF-8 strings
            )

            # Check if the key exists
            if redis_client.exists('num_vulnerabilities_stats'):
                self.stdout.write(self.style.SUCCESS("'num_vulnerabilities_stats' key exists in Redis."))
                vulnerabilities_stats = redis_client.hgetall('num_vulnerabilities_stats')

                if vulnerabilities_stats:
                    self.stdout.write("Vulnerabilities data:")
                    for key, value in vulnerabilities_stats.items():
                        self.stdout.write(f"{key}: {value}")
                else:
                    self.stdout.write(self.style.WARNING("'num_vulnerabilities_stats' key is empty."))
            else:
                self.stdout.write(self.style.WARNING("'num_vulnerabilities_stats' key does not exist in Redis."))

        except redis.ConnectionError as conn_err:
            self.stderr.write(self.style.ERROR(f"Redis connection error: {conn_err}"))
        except redis.RedisError as redis_err:
            self.stderr.write(self.style.ERROR(f"Redis error: {redis_err}"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"An unexpected error occurred: {e}"))
