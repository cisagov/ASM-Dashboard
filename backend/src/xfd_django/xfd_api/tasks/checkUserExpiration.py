"""CheckUserExpiration."""
# Standard Python Libraries
from datetime import timedelta
import os

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
import django
from django.utils.timezone import now

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


# Third-Party Libraries
from xfd_api.helpers.email import send_email
from xfd_api.models import User

# AWS Configuration
cognito_client = boto3.client("cognito-idp", region_name=os.getenv("AWS_REGION"))
user_pool_id = os.getenv("REACT_APP_USER_POOL_ID")


def check_user_expiration():
    """Check user inactivity and take actions: notify (30 days), deactivate (45 days), and delete (90 days)."""
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
        body = """
        Hello {firstName} {lastName},

        Your account has been inactive for over 30 days. If your account reaches 45 days of inactivity,
        your password will be reset, requiring action to reactivate your account.

        Thank you,
        The Crossfeed Team
        """.format(
            firstName=user.firstName, lastName=user.lastName
        )
        send_email(user.email, subject, body)
        print("30-day inactivity notice sent to {}.".format(user.email))

    # Users to deactivate (45 days of inactivity)
    users_to_deactivate = User.objects.filter(
        lastLoggedIn__lt=cutoff_45_days, lastLoggedIn__gte=cutoff_90_days
    )

    for user in users_to_deactivate:
        subject = "Account Deactivation Notice"
        body = """
        Hello {firstName} {lastName},

        Your account has been inactive for over 45 days. As a result, your password has been reset.
        You will need to set a new password the next time you log in. If your account reaches 90 days of inactivity,
        it will be removed, requiring action to recreate your account.

        Thank you,
        The Crossfeed Team
        """.format(
            firstName=user.firstName, lastName=user.lastName
        )
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
            print(
                "Password reset for user {} due to 45 days of inactivity.".format(
                    user.email
                )
            )
        except ClientError as e:
            print("Error resetting password for {}: {}".format(user.email, e))

    # Users to remove (90 days of inactivity)
    users_to_remove = User.objects.filter(lastLoggedIn__lt=cutoff_90_days)

    for user in users_to_remove:
        subject = "Account Removal Notice"
        body = """
        Hello {firstName} {lastName},

        Your account has been inactive for over 90 days and has been removed.
        You will need to recreate your account if you wish to use our services again.

        Thank you,
        The Crossfeed Team
        """.format(
            firstName=user.firstName, lastName=user.lastName
        )
        # Notify user of account removal
        send_email(user.email, subject, body)

        # Remove the user from Cognito and the database
        try:
            # Remove from Cognito
            cognito_client.admin_delete_user(
                UserPoolId=user_pool_id,
                Username=user.cognitoId,
            )
            print("Removed user {} from Cognito.".format(user.email))

            # Remove from database
            user.delete()
            print(
                "Removed user {} from the database due to 90 days of inactivity.".format(
                    user.email
                )
            )
        except ClientError as e:
            print("Error removing user {}: {}".format(user.email, e))


def handler(event, context):
    """AWS Lambda handler for checking user expiration."""
    try:
        check_user_expiration()
        return {
            "statusCode": 200,
            "body": "User expiration check completed successfully.",
        }
    except Exception as e:
        print("Error during user expiration check: {}".format(e))
        return {"statusCode": 500, "body": str(e)}
