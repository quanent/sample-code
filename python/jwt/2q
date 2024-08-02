import jwt
from jwt import PyJWTError, InvalidTokenError, ExpiredSignatureError, InvalidSignatureError, InvalidAudienceError
from cryptography.hazmat.primitives import serialization

# Sample token and public key
token = "your.jwt.token.here"
public_key = """
-----BEGIN PUBLIC KEY-----
YOUR_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
"""

def validate_jwt_rs256(token, public_key):
    try:
        # Decode the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],  # Use the correct algorithm
            options={"verify_exp": True}  # Verify expiration
        )
        
        # Successfully decoded token
        print("Token is valid.")
        print("Payload:", payload)
        return payload

    except ExpiredSignatureError:
        print("Token has expired.")
    except InvalidSignatureError:
        print("Signature verification failed.")
    except InvalidAudienceError:
        print("Invalid audience.")
    except InvalidTokenError:
        print("Invalid token.")
    except PyJWTError as e:
        print("Token validation failed:", str(e))
        
    return None

# Validate the JWT with RS256
payload = validate_jwt_rs256(token, public_key)

