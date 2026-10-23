"""Local web dashboard for QuantumVault.

The server only ever listens on the loopback interface and is hardened
against the usual attacks on local web apps:

* Host header allow-list (blocks DNS-rebinding attacks).
* Per-launch CSRF token required on every state-changing request, plus an
  Origin check.
* Session cookie is HttpOnly, SameSite=Strict and random per launch.
* Strict Content-Security-Policy with no inline scripts.
* Responses are never cached.
* The vault locks itself after a period of inactivity.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, make_response, render_template, request

from . import __version__
from .generator import (
    DEFAULT_LENGTH,
    MAX_LENGTH,
    MIN_ENTROPY_BITS,
    MIN_LENGTH,
    PasswordOptions,
    PasswordPolicyError,
    generate,
)
from .vault import (
    MIN_MASTER_PASSWORD_LENGTH,
    EntryNotFoundError,
    InvalidMasterPasswordError,
    Vault,
    VaultError,
    VaultLockedError,
)

SESSION_COOKIE = "qv_session"
DEFAULT_IDLE_TIMEOUT = 10 * 60  # seconds


def create_app(
    vault_path: str | Path,
    *,
    port: int = 8765,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    kdf_params: dict | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    vault = Vault(vault_path, kdf_params=kdf_params)
    csrf_token = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    session = {"token": None, "last_seen": 0.0}
    session_lock = threading.Lock()
    unlock_failures = {"count": 0, "until": 0.0}

    app.extensions["quantumvault"] = vault

    # -- session helpers ---------------------------------------------------

    def start_session() -> str:
        with session_lock:
            session["token"] = secrets.token_urlsafe(32)
            session["last_seen"] = time.monotonic()
            return session["token"]

    def end_session() -> None:
        with session_lock:
            session["token"] = None
        vault.lock()

    def session_valid() -> bool:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        with session_lock:
            token = session["token"]
            if not token or not vault.unlocked:
                return False
            if time.monotonic() - session["last_seen"] > idle_timeout:
                session["token"] = None
                vault.lock()
                return False
            if not hmac.compare_digest(cookie.encode(), token.encode()):
                return False
            session["last_seen"] = time.monotonic()
            return True

    def requires_unlock(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session_valid():
                return error("Vault is locked.", 401)
            return view(*args, **kwargs)

        return wrapper

    def error(message: str, status: int = 400):
        return jsonify({"error": message}), status

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400)
        return data

    def options_from(data: dict) -> PasswordOptions:
        try:
            return PasswordOptions(
                length=int(data.get("length", DEFAULT_LENGTH)),
                lowercase=bool(data.get("lowercase", True)),
                uppercase=bool(data.get("uppercase", True)),
                digits=bool(data.get("digits", True)),
                symbols=bool(data.get("symbols", True)),
                exclude_ambiguous=bool(data.get("exclude_ambiguous", False)),
            )
        except (TypeError, ValueError):
            raise PasswordPolicyError("Invalid password options.") from None

    # -- request hardening -------------------------------------------------

    @app.before_request
    def guard():
        if request.host not in allowed_hosts:
            abort(403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                abort(403)
            sent = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sent.encode(), csrf_token.encode()):
                abort(403)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(400)
    def bad_request(_):
        return error("Expected a JSON request body.", 400)

    @app.errorhandler(403)
    def forbidden(_):
        return error("Forbidden.", 403)

    @app.errorhandler(413)
    def too_large(_):
        return error("Request too large.", 413)

    # -- pages -------------------------------------------------------------

    @app.get("/")
    def index():
        return render_template("index.html", csrf_token=csrf_token, version=__version__)

    # -- API: vault lifecycle ---------------------------------------------

    @app.get("/api/status")
    def status():
        return jsonify(
            {
                "initialized": vault.exists,
                "unlocked": session_valid(),
                "policy": {
                    "min_entropy_bits": MIN_ENTROPY_BITS,
                    "min_length": MIN_LENGTH,
                    "max_length": MAX_LENGTH,
                    "default_length": DEFAULT_LENGTH,
                    "min_master_password_length": MIN_MASTER_PASSWORD_LENGTH,
                    "idle_timeout_seconds": idle_timeout,
                },
            }
        )

    def unlocked_response():
        response = make_response(jsonify({"unlocked": True}))
        response.set_cookie(
            SESSION_COOKIE,
            start_session(),
            httponly=True,
            samesite="Strict",
            path="/",
        )
        return response

    @app.post("/api/setup")
    def setup():
        data = body()
        password = data.get("master_password")
        confirm = data.get("confirm_password")
        if not isinstance(password, str) or password != confirm:
            return error("Passwords do not match.")
        try:
            vault.create(password)
        except VaultError as exc:
            return error(str(exc))
        return unlocked_response()

    @app.post("/api/unlock")
    def unlock():
        now = time.monotonic()
        if now < unlock_failures["until"]:
            wait = int(unlock_failures["until"] - now) + 1
            return error(f"Too many attempts. Try again in {wait} seconds.", 429)
        password = body().get("master_password")
        if not isinstance(password, str):
            return error("Master password is required.")
        try:
            vault.unlock(password)
        except InvalidMasterPasswordError as exc:
            unlock_failures["count"] += 1
            if unlock_failures["count"] >= 3:
                # Exponential back-off on repeated failures.
                unlock_failures["until"] = now + min(2 ** unlock_failures["count"], 300)
            return error(str(exc), 401)
        except VaultError as exc:
            return error(str(exc))
        unlock_failures["count"] = 0
        return unlocked_response()

    @app.post("/api/lock")
    def lock():
        end_session()
        response = make_response(jsonify({"unlocked": False}))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # -- API: generation & entries ----------------------------------------

    @app.post("/api/generate")
    @requires_unlock
    def generate_preview():
        try:
            result = generate(options_from(body()))
        except PasswordPolicyError as exc:
            return error(str(exc))
        return jsonify(
            {
                "password": result.password,
                "entropy_bits": round(result.entropy_bits, 2),
                "post_quantum_bits": round(result.post_quantum_bits, 2),
            }
        )

    @app.get("/api/entries")
    @requires_unlock
    def list_entries():
        return jsonify({"entries": [e.summary() for e in vault.list_entries()]})

    @app.post("/api/entries")
    @requires_unlock
    def create_entry():
        data = body()
        try:
            result = generate(options_from(data.get("options") or {}))
            entry = vault.add_entry(
                title=str(data.get("title", "")),
                password=result.password,
                entropy_bits=result.entropy_bits,
                notes=str(data.get("notes", "")),
            )
        except (PasswordPolicyError, VaultError) as exc:
            return error(str(exc))
        return jsonify({"entry": entry.summary(), "password": entry.password}), 201

    @app.get("/api/entries/<entry_id>/password")
    @requires_unlock
    def reveal(entry_id):
        try:
            entry = vault.get_entry(entry_id)
        except EntryNotFoundError:
            return error("Entry not found.", 404)
        return jsonify({"password": entry.password})

    @app.patch("/api/entries/<entry_id>")
    @requires_unlock
    def update_entry(entry_id):
        data = body()
        try:
            entry = vault.update_entry(
                entry_id,
                title=data.get("title") if isinstance(data.get("title"), str) else None,
                notes=data.get("notes") if isinstance(data.get("notes"), str) else None,
            )
        except EntryNotFoundError:
            return error("Entry not found.", 404)
        except VaultError as exc:
            return error(str(exc))
        return jsonify({"entry": entry.summary()})

    @app.post("/api/entries/<entry_id>/regenerate")
    @requires_unlock
    def regenerate(entry_id):
        try:
            result = generate(options_from(body().get("options") or {}))
            entry = vault.update_entry(
                entry_id, password=result.password, entropy_bits=result.entropy_bits
            )
        except EntryNotFoundError:
            return error("Entry not found.", 404)
        except (PasswordPolicyError, VaultError) as exc:
            return error(str(exc))
        return jsonify({"entry": entry.summary(), "password": entry.password})

    @app.delete("/api/entries/<entry_id>")
    @requires_unlock
    def delete_entry(entry_id):
        try:
            vault.delete_entry(entry_id)
        except EntryNotFoundError:
            return error("Entry not found.", 404)
        return jsonify({"deleted": entry_id})

    @app.errorhandler(VaultLockedError)
    def locked(_):
        return error("Vault is locked.", 401)

    return app
