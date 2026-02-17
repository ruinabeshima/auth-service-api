from src.core.email_service import send_account_verification_email, send_password_reset_email
from unittest.mock import patch
from src.schemas import SendVerificationEmailRequest, SendResetEmailRequest


class TestAccountVerification:

    @patch("src.core.email_service.resend.Emails.send")
    def test_account_verification_email(self, mock_send):
        mock_send.return_value = {"id": "user123"}

        request = SendVerificationEmailRequest(
            to_email="user123@email.com", verification_token="token-123"
        )

        response = send_account_verification_email(request)

        assert response == {"id": "user123"}

        # Verifies send function was called exactly one time
        mock_send.assert_called_once()

        # Extracting arguments passed to the mocked function
        call_args = mock_send.call_args[0][0]
        assert call_args["to"] == "user123@email.com"
        assert "token-123" in call_args["html"]

    @patch("src.core.email_service.resend.Emails.send")
    def test_account_verification_email_failure(self, mock_send):
        mock_send.side_effect = Exception("API Error")

        request = SendVerificationEmailRequest(
            to_email="user123@email.com", verification_token="token-123"
        )

        response = send_account_verification_email(request)

        assert isinstance(response, dict)
        assert "Failed to send email" in response["message"]  # type:ignore


class TestPasswordReset:

    @patch("src.core.email_service.resend.Emails.send")
    def test_password_reset_email(self, mock_send):
        mock_send.return_value = {"id": "user123"}

        request = SendResetEmailRequest(
            to_email="user123@email.com", reset_token="token-123"
        )

        response = send_password_reset_email(request)

        assert response == {"id": "user123"}

        # Verifies send function was called exactly one time
        mock_send.assert_called_once()

        # Extracting arguments passed to the mocked function
        call_args = mock_send.call_args[0][0]
        assert call_args["to"] == "user123@email.com"
        assert "token-123" in call_args["html"]

    @patch("src.core.email_service.resend.Emails.send")
    def test_password_reset_email_failure(self, mock_send):
        mock_send.side_effect = Exception("API Error")

        request = SendResetEmailRequest(
            to_email="user123@email.com", reset_token="token-123"
        )

        response = send_password_reset_email(request)

        assert isinstance(response, dict)
        assert "Failed to send email" in response["message"]  # type:ignore
