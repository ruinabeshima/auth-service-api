import os
import resend
from .schemas import SendResetEmailRequest, SendVerificationEmailRequest
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")
app_url = os.getenv("APP_URL")


def send_password_reset_email(request: SendResetEmailRequest):

    # Creating link to reset password
    reset_link = f"{app_url}/reset-password?token={request.reset_token}"

    try:
        response = resend.Emails.send(
            {
                "from": "onboarding@resend.dev",
                "to": request.to_email,
                "subject": "Password Reset Request",
                "html": f"""
                  <h2>Password Reset</h2>
                  <p>You requested a password reset. Click the link below to reset: </p>
                  <a href="{reset_link}">Reset Password</a>
                  <p>This link expires in 5 minutes</p>
                """,
            }
        )
        return response
    except Exception as error:
        return {"message": f"Failed to send email: {error}"}


def send_account_verification_email(request: SendVerificationEmailRequest):

    verification_link = f"{app_url}/verify-account?token={request.verification_token}"

    try:
        response = resend.Emails.send(
            {
                "from": "onboarding@resend.dev",
                "to": request.to_email,
                "subject": "Account Verification",
                "html": f"""
                  <h2>Verify Account</h2>
                  <p>You signed up to our website. Click the link below to verify your account:</p>
                  <a href="{verification_link}">Verify account</a>
                  <p>This link expires in 5 minutes</p>
                """,
            }
        )
        return response
    except Exception as error:
        return {"message": f"Failed to send email: {error}"}
