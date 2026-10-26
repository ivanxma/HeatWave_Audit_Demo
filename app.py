#!/usr/bin/env python3
"""HeatWave Enterprise Audit demonstrator. Run one process for session affinity."""

import json
import os
import secrets
import threading
import time
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from modules.analytics import COLUMNS
from modules.audit import CLASSES, build_plan, execute_plan
from modules.errors import mysql_error_message
from modules.mysql_util import open_connection

ROOT = Path(__file__).resolve().parent


def create_app(test_config=None):
    app = Flask(__name__)
    private = {}
    if os.environ.get("AUDIT_CONFIG_FILE"):
        private = json.loads(
            Path(os.environ["AUDIT_CONFIG_FILE"]).expanduser().read_text()
        )
    app.config.update(
        SECRET_KEY=os.environ.get("AUDIT_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_NAME="heatwave_audit_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("AUDIT_COOKIE_SECURE") == "1",
        MAX_CONTENT_LENGTH=256 * 1024,
        PROFILE_STORE=str(ROOT / "generated" / "profiles.json"),
        DEMO_ENABLED=True,
        SESSION_TTL=3600,
    )
    app.config.update(private)
    if test_config:
        app.config.update(test_config)
    records, lock = {}, threading.RLock()
    app.extensions["audit_sessions"] = records
    app.extensions["audit_lock"] = lock

    def close_record(sid):
        with lock:
            rec = records.pop(sid, None)
        if rec and rec.get("connection"):
            with rec["lock"]:
                try:
                    rec["connection"].close()
                except Exception:
                    pass
                if rec.get("tunnel"):
                    rec["tunnel"].stop()

    def profiles():
        path = Path(app.config["PROFILE_STORE"])
        if not path.exists():
            return {}
        return json.loads(path.read_text()).get("profiles", {})

    def save_profile(name, profile):
        with lock:
            all_profiles = profiles()
            if name in all_profiles:
                raise ValueError("That profile name already exists. Choose a new name.")
            all_profiles[name] = profile
            path = Path(app.config["PROFILE_STORE"])
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"profiles": all_profiles}, indent=2))
            tmp.chmod(0o600)
            tmp.replace(path)

    def new_session(**data):
        close_record(session.get("sid"))
        session.clear()
        with lock:
            sid = secrets.token_urlsafe(32)
            records[sid] = dict(
                csrf=secrets.token_urlsafe(32),
                expires=time.time() + app.config["SESSION_TTL"],
                lock=threading.RLock(),
                notifications=[],
                plans={},
                reader=False,
                **data,
            )
            session["sid"] = sid
        return records[sid]

    @app.before_request
    def prepare():
        with lock:
            expired = [
                sid for sid, rec in records.items() if rec["expires"] <= time.time()
            ]
        for sid in expired:
            close_record(sid)
        with lock:
            rec = records.get(session.get("sid"))
        if rec is None:
            session.clear()
            rec = new_session(auth=False, demo=False)
        g.rec = rec
        if request.method == "POST" and not secrets.compare_digest(
            str(request.headers.get("X-CSRF-Token") or request.form.get("csrf") or ""),
            rec["csrf"],
        ):
            return jsonify(
                error="This form expired. Reload the page and try again."
            ), 400

    @app.after_request
    def headers(response):
        if (
            request.path.startswith("/api/")
            and response.status_code >= 400
            and getattr(g, "rec", {}).get("auth")
        ):
            body = response.get_json(silent=True) or {}
            if body.get("error"):
                with g.rec["lock"]:
                    g.rec["notifications"].insert(
                        0,
                        dict(
                            message=body["error"],
                            time=time.strftime("%H:%M:%S"),
                            category="error",
                        ),
                    )
                    del g.rec["notifications"][30:]
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    def authenticated(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.rec.get("auth"):
                if request.path.startswith("/api/"):
                    return jsonify(error="Sign in to continue."), 401
                return redirect(url_for("login"))
            with g.rec["lock"]:
                if not g.rec["demo"]:
                    try:
                        cur = g.rec["connection"].cursor(buffered=True)
                        cur.execute("SELECT 1")
                        cur.fetchone()
                        cur.close()
                    except Exception:
                        close_record(session.get("sid"))
                        session.clear()
                        if request.path.startswith("/api/"):
                            return jsonify(
                                error="Database connection lost. Sign in again; the read sequence was closed."
                            ), 401
                        return redirect(url_for("login"))
                return fn(*args, **kwargs)

        return wrapped

    @app.context_processor
    def context():
        return dict(
            app_title="HeatWave Enterprise Audit", csrf=g.rec["csrf"], rec=g.rec
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            connection = tunnel = None
            try:
                if request.form.get("intent") == "demo":
                    if not app.config["DEMO_ENABLED"]:
                        raise ValueError("Sample mode is disabled.")
                    new_session(
                        auth=True,
                        demo=True,
                        username="Sample user",
                        profile_name="Sample workspace",
                        profile={},
                        audit_database="mysql_audit",
                    )
                    return redirect(url_for("workspace", page="filters"))
                name = request.form.get("profile", "")
                creating = request.form.get("intent") == "create"
                if creating:
                    name = request.form.get("name", "").strip()
                    if (
                        not name
                        or len(name) > 64
                        or any(
                            c
                            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
                            for c in name
                        )
                    ):
                        raise ValueError(
                            "Use a profile name with letters, numbers, dot, underscore or hyphen."
                        )
                    if name in profiles():
                        raise ValueError("That profile name already exists.")
                    host = request.form.get("host", "").strip()
                    if not host or len(host) > 255 or any(c in host for c in "/@\x00"):
                        raise ValueError("Enter a valid MySQL host.")
                    port = int(request.form.get("port", 3306))
                    if not 1 <= port <= 65535:
                        raise ValueError("Port must be between 1 and 65535.")
                    mode = request.form.get("ssl_mode", "REQUIRED")
                    if mode not in (
                        "REQUIRED",
                        "VERIFY_CA",
                        "VERIFY_IDENTITY",
                        "DISABLED",
                    ):
                        raise ValueError("Unsupported TLS mode.")
                    profile = dict(
                        host=host,
                        port=port,
                        ssl_mode=mode,
                        ssl_ca=request.form.get("ssl_ca", "").strip(),
                    )
                else:
                    profile = profiles().get(name)
                    if not profile:
                        raise ValueError("Choose or create a connection profile.")
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if not username or not password:
                    raise ValueError("MySQL username and password are required.")
                connection, tunnel = open_connection(profile, username, password)
                cur = connection.cursor(buffered=True)
                cur.execute("SELECT 1")
                cur.fetchone()
                cur.close()
                if creating:
                    save_profile(name, profile)
                rec = new_session(
                    auth=True,
                    demo=False,
                    username=username,
                    profile_name=name,
                    profile=profile,
                    connection=connection,
                    password=password,
                    tunnel=tunnel,
                    audit_database="mysql_audit",
                )
                connection = None
                # Audit features may be unavailable without blocking ordinary MySQL login.
                try:
                    cur = rec["connection"].cursor(buffered=True)
                    cur.execute("SHOW VARIABLES LIKE 'audit_log_database'")
                    row = cur.fetchone()
                    cur.close()
                    if row:
                        rec["audit_database"] = row[1]
                except Exception:
                    pass
                return redirect(url_for("workspace", page="filters"))
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Connection failed. Check the profile, TLS settings, network access and MySQL credentials."
            finally:
                if connection:
                    connection.close()
                    if tunnel:
                        tunnel.stop()
        return render_template(
            "login.html",
            profile_names=sorted(profiles()),
            error=error,
            demo_enabled=app.config["DEMO_ENABLED"],
        )

    @app.route("/")
    def index():
        return redirect(
            url_for("workspace", page="filters")
            if g.rec.get("auth")
            else url_for("login")
        )

    @app.get("/<page>")
    @authenticated
    def workspace(page):
        if page not in ("filters", "reader", "analytics"):
            return redirect(url_for("workspace", page="filters"))
        return render_template(
            "dashboard.html", page=page, classes=CLASSES, columns=COLUMNS
        )

    @app.post("/logout")
    def logout():
        close_record(session.get("sid"))
        session.clear()
        return redirect(url_for("login"))

    @app.post("/api/preview")
    @authenticated
    def preview():
        try:
            data = request.get_json()
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            plan = build_plan(data, g.rec["audit_database"])
            token = secrets.token_urlsafe(24)
            g.rec["plans"].clear()
            g.rec["plans"][token] = (time.time() + 600, plan)
            return jsonify(
                token=token,
                sql="\n\n".join(s["display"] for s in plan["statements"]),
                definition=plan.get("definition"),
            )
        except (ValueError, TypeError, AttributeError) as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/execute")
    @authenticated
    def execute():
        data = request.get_json(silent=True) or {}
        saved = g.rec["plans"].pop(data.get("token", ""), None)
        if not saved or saved[0] < time.time():
            return jsonify(error="Preview the SQL again before executing."), 400
        plan = saved[1]
        if (
            plan["action"] == "next"
            or plan.get("reader_mode") == "next"
            or plan.get("timing") == "next"
        ) and not g.rec["reader"]:
            return jsonify(
                error="Start a read sequence before choosing Read next."
            ), 400
        try:
            if g.rec["demo"]:
                from modules.demo import demo_execute

                result = demo_execute(g.rec, plan)
            else:
                result = execute_plan(g.rec["connection"], plan)
            if plan["action"] in ("read", "next", "analytics_query", "query_view"):
                g.rec["reader"] = True
            if plan["action"] == "close":
                g.rec["reader"] = False
            if plan["action"] == "create_view":
                g.rec["reader"] = False
            message = (
                "Sample operation completed: " if g.rec["demo"] else "Executed: "
            ) + plan["action"].replace("_", " ")
            g.rec["notifications"].insert(
                0,
                dict(
                    message=message, time=time.strftime("%H:%M:%S"), category="success"
                ),
            )
            del g.rec["notifications"][30:]
            return jsonify(**result, message=message)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except Exception as exc:
            if getattr(exc, "errno", None) == 3200:
                g.rec["reader"] = False
            return jsonify(
                error=mysql_error_message(exc, (g.rec.get("password"),))
            ), 400

    @app.get("/api/notifications")
    @authenticated
    def notifications():
        return jsonify(messages=g.rec["notifications"])

    @app.post("/api/notifications/clear")
    @authenticated
    def clear_notifications():
        g.rec["notifications"].clear()
        return jsonify(ok=True)

    return app


if __name__ == "__main__":
    create_app().run(
        host=os.environ.get("AUDIT_BIND", "127.0.0.1"),
        port=int(os.environ.get("AUDIT_PORT", "5055")),
        threaded=True,
    )
