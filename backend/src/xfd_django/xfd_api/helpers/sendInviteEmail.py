# Standard Python Libraries
import os
from typing import Optional

# Third-Party Libraries
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException


async def send_email(recipient: str, subject: str, body: str):
    ses_client = boto3.client("ses", region_name="us-east-1")
    try:
        response = ses_client.send_email(
            Source=os.getenv("CROSSFEED_SUPPORT_EMAIL_SENDER"),
            Destination={
                "ToAddresses": [recipient],
            },
            Message={
                "Subject": {
                    "Data": subject,
                },
                "Body": {
                    "Text": {
                        "Data": body,
                    },
                },
            },
            ReplyToAddresses=[os.getenv("CROSSFEED_SUPPORT_EMAIL_REPLYTO")],
        )
    except (BotoCoreError, ClientError) as e:
        print(f"Error sending email: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send email")


async def send_invite_email(email: str, organization: Optional[str] = None):
    staging = os.getenv("NODE_ENV") != "production"
    frontend_domain = os.getenv("FRONTEND_DOMAIN")
    support_email = os.getenv("CROSSFEED_SUPPORT_EMAIL_REPLYTO")

    subject = "CyHy Dashboard Invitation"
    body = f"""
    Hi there,

    You've been invited to join {f"the {organization} organization on " if organization else ""}CyHy Dashboard. To accept the invitation and start using CyHy Dashboard, sign on at {frontend_domain}/signup.

    CyHy Dashboard access instructions:

    1. Visit {frontend_domain}/signup.
    2. Select "Create Account."
    3. Enter your email address and a new password for CyHy Dashboard.
    4. A confirmation code will be sent to your email. Enter this code when you receive it.
    5. You will be prompted to enable MFA. Scan the QR code with an authenticator app on your phone, such as Microsoft Authenticator. Enter the MFA code you see after scanning.
    6. After configuring your account, you will be redirected to CyHy Dashboard.

    For more information on using CyHy Dashboard, view the CyHy Dashboard user guide at https://docs.crossfeed.cyber.dhs.gov/user-guide/quickstart/.

    If you encounter any difficulties, please feel free to reply to this email (or send an email to {support_email}).
    """

    await send_email(email, subject, body)
