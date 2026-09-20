"""Authentication module generating JWT tokens with RS256."""

import jwt


def create_jwt_token(payload: dict, private_key: str) -> str:
    """Generate a signed JWT token using RS256."""
    return jwt.encode(payload, private_key, algorithm="RS256")
