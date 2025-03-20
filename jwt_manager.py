"""
Provides management for JWT tokens and securely storing them in the OS's Keyring Store.
"""
import json
import time

import jwt
import keyring


class JwtManager:
    """
    Class for managing JWT tokens and securely storing them in the OS's Keyring Store.
    """

    def __init__(self, session, service_name, default_token_lifespan=3600):
        self.session = session
        self.service_name = service_name
        self.default_token_lifespan = default_token_lifespan
        self.token_info = None
        self._load_cached_token()

    def _load_cached_token(self):
        token_data = keyring.get_password(self.service_name, "TOKEN")
        if not token_data:
            self.clear_token()
            return

        try:
            data = json.loads(token_data)
            raw_token = data.get("token")
            if not raw_token:
                self.clear_token()
                return

            issued_at, expires_at = self._parse_timestamps(raw_token)
            if issued_at is None or expires_at is None:
                self.clear_token()
                return

            csrf_token = self._parse_csrf(raw_token)
            self.token_info = {
                "token": raw_token,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "csrf_token": csrf_token
            }
            self.session.cookies.set("TOKEN", raw_token)

        except (ValueError, KeyError):
            self.clear_token()

    def _parse_csrf(self, token):
        """
        Extract the csrfToken from the token's payload.
        If parsing fails, return an empty string (caller can clear).
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload.get("csrfToken", "")

        # pylint: disable=broad-except
        except Exception:
            return ""

    def _parse_timestamps(self, token):
        """
        Extract iat (issued at) and exp (expires at) from the token.
        Return (None, None) if parsing fails.
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            issued_at = payload.get("iat", int(time.time()))
            expires_at = payload.get(
                "exp", issued_at + self.default_token_lifespan)
            return issued_at, expires_at

        # pylint: disable=broad-except
        except Exception:
            return None, None

    def save_token(self, token):
        """
        Save a newly acquired token to keyring if it's valid. If invalid, do nothing.
        """
        issued_at, expires_at = self._parse_timestamps(token)

        if issued_at is None or expires_at is None:
            self.clear_token()
            return

        csrf_token = self._parse_csrf(token)

        if not csrf_token:
            self.clear_token()
            return

        self.token_info = {
            "token": token,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "csrf_token": csrf_token
        }
        keyring.set_password(
            self.service_name,
            "TOKEN",
            json.dumps({
                "token": token,
                "issued_at": issued_at,
                "expires_at": expires_at
            })
        )
        self.session.cookies.set("TOKEN", token)

    def clear_token(self):
        """Remove the token from memory and from the keyring."""
        self.token_info = None

        try:
            self.session.cookies.pop("TOKEN")
        except KeyError:
            pass

        try:
            keyring.delete_password(self.service_name, "TOKEN")

        # pylint: disable=broad-except
        except Exception:
            pass

    def is_token_valid(self):
        """
        Return True if the token is valid and not expired.
        Otherwise, clear it and return False.
        """
        if not self.token_info:
            return False

        if time.time() > self.token_info["expires_at"]:
            self.clear_token()
            return False
        return True

    def get_csrf_token(self):
        """
        Return the csrfToken if available, else empty string.
        """
        if self.token_info:
            return self.token_info.get("csrf_token", "")
        return ""
