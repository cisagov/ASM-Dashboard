# Standard Python Libraries
from datetime import datetime
import os
import random
from urllib.parse import urlparse

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError


class S3Client:
    def __init__(self, is_local=None):
        self.is_local = (
            is_local
            if is_local is not None
            else bool(os.getenv("IS_OFFLINE") or os.getenv("IS_LOCAL"))
        )

        if self.is_local:
            self.s3 = boto3.client(
                "s3",
                endpoint_url="http://minio:9000",
                config=boto3.session.Config(s3={"addressing_style": "path"}),
            )
        else:
            self.s3 = boto3.client(
                "s3",
                config=boto3.session.Config(
                    s3={"addressing_style": "virtual"},
                    retries={"max_attempts": 3},
                    http={"keep_alive": False},
                ),
            )

    def save_csv(self, body, name=""):
        """Saves a CSV file in S3 and returns a temporary URL for access"""
        try:
            key = f"{random.random()}/{name}-{datetime.utcnow().isoformat()}.csv"
            bucket = os.getenv("EXPORT_BUCKET_NAME")

            # Save CSV to S3
            self.s3.put_object(
                Bucket=bucket, Key=key, Body=body, ContentType="text/csv"
            )

            # Generate signed URL
            url = self.s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=60 * 5,
            )
            return url.replace("minio:9000", "localhost:9000") if self.is_local else url
        except ClientError as e:
            print("Error saving CSV to S3: %s", e)
            raise

    def export_report(self, report_name, org_id):
        """Generates a presigned URL for a report"""
        try:
            key = f"{org_id}/{report_name}"
            bucket = os.getenv("REPORTS_BUCKET_NAME")

            url = self.s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=60 * 5,
            )
            return url.replace("minio:9000", "localhost:9000") if self.is_local else url
        except ClientError as e:
            print("Error exporting report from S3: %s", e)
            raise

    def list_reports(self, org_id):
        """Lists all reports in a specified organization's folder"""
        try:
            bucket = os.getenv("REPORTS_BUCKET_NAME")
            prefix = f"{org_id}/"

            response = self.s3.list_objects_v2(
                Bucket=bucket, Prefix=prefix, Delimiter=""
            )
            return response.get("Contents", [])
        except ClientError as e:
            print("Error listing reports from S3: %s", e)
            raise

    def pull_daily_vs(self, filename):
        """Retrieves a specified daily VS file from S3"""
        bucket = os.getenv("VS_BUCKET_NAME", "vs-extracts")

        try:
            response = self.s3.head_object(Bucket=bucket, Key=filename)
            if response:
                print(f"File '{filename}' exists in bucket {bucket}.")
        except self.s3.exceptions.NoSuchKey:
            print(f"File '{filename}' does not exist in bucket {bucket}.")
            return None
        except ClientError as e:
            print("Error checking for file in S3: %s", e)
            raise

        try:
            response = self.s3.get_object(Bucket=bucket, Key=filename)
            return response["Body"].read() if "Body" in response else None
        except ClientError as e:
            print("Error downloading file from S3: %s", e)
            raise

    def get_email_asset(self, file_name):
        """Retrieves an email template asset from S3"""
        bucket = os.getenv("EMAIL_BUCKET_NAME")

        try:
            response = self.s3.get_object(Bucket=bucket, Key=file_name)
            return (
                response["Body"].read().decode("utf-8") if "Body" in response else None
            )
        except ClientError as e:
            print("Error retrieving email asset from S3: %s", e)
            raise
