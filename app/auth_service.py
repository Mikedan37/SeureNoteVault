from webauthn import verify_authentication_response
from webauthn.helpers import bytes_to_base64url, generate_challenge


def generate_webauthn_challenge():
    """
    Generate a WebAuthn challenge for the user.
    """
    challenge = generate_challenge()  # Ensures 'challenge' is passed as bytes.
    return bytes_to_base64url(challenge)  # Convert to a Base64 URL-safe string


class AuthenticationResponseVerificationError:
    pass


def verify_webauthn_credential(credential, challenge, rp_id, user_verification):
    """
    Verify the WebAuthn credential against the challenge and Relying on Party settings.

    Args:
        credential (dict): The credential response from the client.
        challenge (str): The original WebAuthn challenge.
        rp_id (str): The Relying on Party ID (e.g., your domain name).
        user_verification (str): The expected user verification ("preferred", "required", etc.).

    Returns:
        dict: Verification results or error details.
    """
    try:
        authentication_credential = credential

        verified_authentication_response = verify_authentication_response(
            credential=authentication_credential,
            expected_challenge=challenge.encode('utf-8'),  # Convert str to bytes
            expected_rp_id=rp_id,
            expected_origin="https://your-domain.com",  # Update this to your app's origin
            require_user_verification=True if user_verification.lower() == "required" else False,
            credential_public_key=b"stored_public_key",  # Replace with the actual bytes value
            credential_current_sign_count=1,  # Replace with the stored sign count
        )

        return {
            "verified": True,
            "credential_id": bytes_to_base64url(verified_authentication_response.credential_id),
        }
    except AuthenticationResponseVerificationError as e:
        return {"verified": False, "error": str(e)}

def extract_user_from_credential(credential):
    """
    Extract the user ID or username from the WebAuthn credential.
    Replace this with actual logic.
    """
    # Example implementation (replace with real logic)
    return credential.get("user_id")