import os
from datetime import datetime, timedelta
from django.utils.timezone import now
from django.db.models import Q
from django.conf import settings
import boto3
import django
from botocore.exceptions import ClientError

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


from xfd_api.models import User
from xfd_api.helpers.email import send_email

# AWS Configuration
cognito_client = boto3.client("cognito-idp", region_name=os.getenv("AWS_REGION"))
user_pool_id = os.getenv("REACT_APP_USER_POOL_ID")


def check_user_expiration():
    """
    Check user inactivity and take actions: notify (30 days), deactivate (45 days), and delete (90 days).
    """

    today = now()
    cutoff_30_days = today - timedelta(days=30)
    cutoff_45_days = today - timedelta(days=45)
    cutoff_90_days = today - timedelta(days=90)

    # Users to notify (30 days of inactivity)
    users_to_notify = User.objects.filter(
        lastLoggedIn__lt=cutoff_30_days, lastLoggedIn__gte=cutoff_45_days
    )

    # Notify users of inactivity (30 days)
    for user in users_to_notify:
        subject = "Account Inactivity Notice"
        body = f"""
        Hello {user.firstName} {user.lastName},

        Your account has been inactive for over 30 days. If your account reaches 45 days of inactivity,
        your password will be reset, requiring action to reactivate your account.

        Thank you,
        The Crossfeed Team
        """
        send_email(user.email, subject, body)
        print(f"30-day inactivity notice sent to {user.email}.")

    # Users to deactivate (45 days of inactivity)
    users_to_deactivate = User.objects.filter(
        lastLoggedIn__lt=cutoff_45_days, lastLoggedIn__gte=cutoff_90_days
    )

    for user in users_to_deactivate:
        subject = "Account Deactivation Notice"
        body = f"""
        Hello {user.firstName} {user.lastName},

        Your account has been inactive for over 45 days. As a result, your password has been reset.
        You will need to set a new password the next time you log in. If your account reaches 90 days of inactivity,
        it will be removed, requiring action to recreate your account.

        Thank you,
        The Crossfeed Team
        """
        # Send inactivity notification
        send_email(user.email, subject, body)

        # Reset the user's password
        try:
            cognito_client.admin_set_user_password(
                UserPoolId=user_pool_id,
                Username=user.cognitoId,
                Password=os.getenv("REACT_APP_RANDOM_PASSWORD"),
                Permanent=False,
            )
            print(f"Password reset for user {user.email} due to 45 days of inactivity.")
        except ClientError as e:
            print(f"Error resetting password for {user.email}: {e}")

    # Users to remove (90 days of inactivity)
    users_to_remove = User.objects.filter(lastLoggedIn__lt=cutoff_90_days)

    for user in users_to_remove:
        subject = "Account Removal Notice"
        body = f"""
        Hello {user.firstName} {user.lastName},

        Your account has been inactive for over 90 days and has been removed.
        You will need to recreate your account if you wish to use our services again.

        Thank you,
        The Crossfeed Team
        """
        # Notify user of account removal
        send_email(user.email, subject, body)

        # Remove the user from Cognito and the database
        try:
            # Remove from Cognito
            cognito_client.admin_delete_user(
                UserPoolId=user_pool_id,
                Username=user.cognitoId,
            )
            print(f"Removed user {user.email} from Cognito.")

            # Remove from database
            user.delete()
            print(f"Removed user {user.email} from the database due to 90 days of inactivity.")
        except ClientError as e:
            print(f"Error removing user {user.email}: {e}")


def handler(event, context):
    """
    AWS Lambda handler for checking user expiration.
    """
    try:
        check_user_expiration()
        return {"statusCode": 200, "body": "User expiration check completed successfully."}
    except Exception as e:
        print(f"Error during user expiration check: {e}")
        return {"statusCode": 500, "body": str(e)}
