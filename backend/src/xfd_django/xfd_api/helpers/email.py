# Standard Python Libraries
import os

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from jinja2 import Template

from .s3_client import S3Client


def _setup_proxy():
    """
    If LZ_PROXY_URL is set in the environment, configure the HTTPS/HTTP proxy.
    This ensures that outbound connections go through the specified proxy.
    """
    proxy_url = os.getenv("LZ_PROXY_URL")
    if proxy_url:
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["HTTP_PROXY"] = proxy_url
    else:
        # If not set, ensure these are not set so traffic is direct
        os.environ.pop("HTTPS_PROXY", None)
        os.environ.pop("HTTP_PROXY", None)


def send_invite_email(email, organization=None):
    """Send an invitation email to the specified address."""

    _setup_proxy()  # Setup proxy if LZ_PROXY_URL is defined

    frontend_domain = settings.FRONTEND_DOMAIN
    reply_to = settings.CROSSFEED_SUPPORT_EMAIL_REPLYTO

    org_name_part = f"the {organization.name} organization on " if organization else ""
    message = f"""
    Hi there,

    You've been invited to join {org_name_part}CyHy Dashboard. To accept the invitation and start using CyHy Dashboard, sign on at {frontend_domain}/signup.

    CyHy Dashboard access instructions:

    1. Visit {frontend_domain}/signup.
    2. Select "Create Account."
    3. Enter your email address and a new password for CyHy Dashboard.
    4. A confirmation code will be sent to your email. Enter this code when you receive it.
    5. You will be prompted to enable MFA. Scan the QR code with an authenticator app on your phone, such as Microsoft Authenticator. Enter the MFA code you see after scanning.
    6. After configuring your account, you will be redirected to CyHy Dashboard.

    For more information on using CyHy Dashboard, view the CyHy Dashboard user guide at https://docs.crossfeed.cyber.dhs.gov/user-guide/quickstart/.

    If you encounter any difficulties, please feel free to reply to this email (or send an email to {reply_to}).
    """
    send_email(email, "CyHy Dashboard Invitation", message)


def send_email(recipient, subject, body):
    """Send an email using AWS SES."""

    _setup_proxy()  # Setup proxy if LZ_PROXY_URL is defined

    ses_client = boto3.client("ses", region_name=os.getenv("EMAIL_REGION"))
    sender = settings.CROSSFEED_SUPPORT_EMAIL_SENDER
    reply_to = settings.CROSSFEED_SUPPORT_EMAIL_REPLYTO

    email_params = {
        "Source": sender,
        "Destination": {"ToAddresses": [recipient]},
        "Message": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        "ReplyToAddresses": [reply_to],
    }

    try:
        ses_client.send_email(**email_params)
        print(f"Email sent to {recipient}")
    except ClientError as e:
        print(f"Error sending email: {e}")


def send_registration_approved_email(
    recipient: str, subject: str, first_name: str, last_name: str, template
):
    """Send registration approved email."""
    try:
        _setup_proxy()  # Setup proxy if LZ_PROXY_URL is defined

        # Initialize S3 client and fetch email template
        client = S3Client()
        html_template = client.get_email_asset(template)

        if not html_template:
            raise ValueError("Email template not found or empty.")

        # Set up the email content with Jinja2 template rendering
        template = Template(html_template)
        data = {
            "firstName": first_name,
            "lastName": last_name,
            "domain": settings.FRONTEND_DOMAIN,
        }
        html_to_send = template.render(data)

        # Email configuration
        sender = settings.CROSSFEED_SUPPORT_EMAIL_SENDER
        reply_to = settings.CROSSFEED_SUPPORT_EMAIL_REPLYTO

        email_params = {
            "Source": sender,
            "Destination": {"ToAddresses": [recipient]},
            "Message": {
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_to_send}},
            },
            "ReplyToAddresses": [reply_to],
        }
        # SES client
        if not settings.IS_LOCAL:
            ses_client = boto3.client("ses", region_name=os.getenv("EMAIL_REGION"))
            # Send email
            ses_client.send_email(**email_params)
            print("Email sent successfully to:", recipient)
        else:
            print(email_params)
            print("Local environment cannot send email")

    except (ClientError, ValueError) as e:
        print("Email error:", e)


def send_registration_denied_email(
    recipient: str, subject: str, first_name: str, last_name: str, template
):
    """Send registration denied email."""
    try:
        _setup_proxy()  # Setup proxy if LZ_PROXY_URL is defined

        # Initialize S3 client and fetch email template
        client = S3Client()
        html_template = client.get_email_asset(template)

        if not html_template:
            raise ValueError("Email template not found or empty.")

        # Set up the email content with Jinja2 template rendering
        template = Template(html_template)
        data = {
            "firstName": first_name,
            "lastName": last_name,
        }
        html_to_send = template.render(data)

        # Email configuration
        sender = settings.CROSSFEED_SUPPORT_EMAIL_SENDER
        reply_to = settings.CROSSFEED_SUPPORT_EMAIL_REPLYTO

        email_params = {
            "Source": sender,
            "Destination": {"ToAddresses": [recipient]},
            "Message": {
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_to_send}},
            },
            "ReplyToAddresses": [reply_to],
        }
        # SES client
        if not settings.IS_LOCAL:
            ses_client = boto3.client("ses", region_name=os.getenv("EMAIL_REGION"))
            # Send email
            ses_client.send_email(**email_params)
            print("Email sent successfully to:", recipient)
        else:
            print(email_params)
            print("Local environment cannot send email")

    except (ClientError, ValueError) as e:
        print("Email error:", e)
