"""Login gov methods."""
# Standard Python Libraries
import json
import os
import secrets

# Third-Party Libraries
import jwt
import requests

discovery_url = (
    os.getenv("LOGIN_GOV_BASE_URL", "") + "/.well-known/openid-configuration"
)

# Load JWK Set (JSON Web Key Set)
try:
    jwk_set = {"keys": [json.loads(os.getenv("LOGIN_GOV_JWT_KEY", ""))]}
except Exception as error:
    print(f"Error: {error}")
    jwk_set = {"keys": [{}]}

# OpenID Connect Client Configuration
client_options = {
    "client_id": os.getenv("LOGIN_GOV_ISSUER"),
    "token_endpoint_auth_method": "private_key_jwt",
    "id_token_signed_response_alg": "RS256",
    "redirect_uris": [os.getenv("LOGIN_GOV_REDIRECT_URI", "")],
    "token_endpoint": os.getenv("LOGIN_GOV_BASE_URL", "") + "/api/openid_connect/token",
}


# Generate random string for nonce and state
def random_string(length):
    """Random string generator."""
    return secrets.token_hex(length // 2)


# Login function that returns authorization URL, state, and nonce
def login():
    """Equivalent function to initiate OpenID Connect login."""
    # Fetch OpenID Connect configuration
    config_response = requests.get(discovery_url, timeout=20)
    config = config_response.json()

    nonce = random_string(32)
    state = random_string(32)

    # Create authorization URL
    authorization_url = (
        f"{config['authorization_endpoint']}?response_type=code"
        f"&client_id={client_options['client_id']}"
        f"&redirect_uri={client_options['redirect_uris'][0]}"
        f"&scope=openid+email"
        f"&nonce={nonce}&state={state}&prompt=select_account"
    )

    return {"url": authorization_url, "state": state, "nonce": nonce}


# Callback function to exchange authorization code for tokens and user info
def callback(body):
    """Equivalent function to handle OpenID Connect callback."""
    config_response = requests.get(discovery_url, timeout=20)
    config = config_response.json()

    # Exchange the authorization code for tokens
    token_response = requests.post(
        config["token_endpoint"],
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": body["code"],
            "client_id": client_options["client_id"],
            "redirect_uri": client_options["redirect_uris"][0],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt.encode(
                {"alg": "RS256"}, jwk_set["keys"][0], algorithm="RS256"
            ),
        },
        timeout=20,  # Timeout in seconds
    )

    token_response_data = token_response.json()

    if "id_token" not in token_response_data:
        raise Exception("ID token not found in the token response")

    id_token = token_response_data["id_token"]

    # Decode the ID token without verifying the signature
    # (optional depending on your security model)
    decoded_token = jwt.decode(id_token, options={"verify_signature": False})
    print(f"Decoded Token from login_gov: {decoded_token}")
    return decoded_token
