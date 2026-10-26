import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import create_app
from modules.analytics import COLUMNS
from modules.audit import build_plan, definition, execute_plan, sql_literal
from modules.mysql_util import ConnectionCache, build_tls_kwargs, escape_sql_literal


class SQLTests(unittest.TestCase):
    def test_bookmark_read_uses_separate_text_arguments(self):
        plan = build_plan(
            {"action": "read", "start_mode": "bookmark", "max_events": 100}
        )
        sql = [s["sql"] for s in plan["statements"]]
        self.assertEqual(len(sql), 5)
        self.assertIn(
            "SET @audit_reader_bookmark = CONVERT(audit_log_read_bookmark() USING utf8mb4)",
            sql,
        )
        self.assertIn("CONVERT(JSON_SET(@audit_reader_bookmark", sql[2])
        self.assertEqual(plan["statements"][2]["params"], (100,))
        self.assertEqual(sql[3], "SELECT @audit_reader_args AS reader_arguments")
        self.assertEqual(sql[4], "SELECT audit_log_read(@audit_reader_args) AS events")

    def test_reader_failure_preserves_server_reason_and_statement(self):
        from mysql.connector import Error

        conn = MagicMock()
        success, warnings, failing = MagicMock(), MagicMock(), MagicMock()
        success.with_rows = False
        success.nextset.return_value = None
        warnings.fetchall.return_value = []
        failure = Error(
            msg="audit_log_read_bookmark UDF failed; No readable log", errno=3200
        )
        failing.execute.side_effect = failure
        conn.cursor.side_effect = [success, warnings, failing]
        with self.assertRaises(Error) as caught:
            execute_plan(conn, build_plan({"action": "read", "start_mode": "bookmark"}))
        self.assertEqual(caught.exception.audit_statement_index, 2)
        self.assertEqual(caught.exception.errno, 3200)
        self.assertIn("No readable log", caught.exception.msg)
        failing.close.assert_called_once()

    def test_reader_positions_and_bounds(self):
        data = dict(
            action="read",
            buffer_size=32768,
            max_events=10,
            start_mode="timestamp",
            timestamp="2026-10-26 12:00:00",
        )
        plan = build_plan(data)
        args = json.loads(plan["statements"][1]["params"][0])
        self.assertEqual(args["start"], {"timestamp": data["timestamp"]})
        self.assertNotIn("id", args)
        plan = build_plan(
            dict(data, start_mode="position", event_id="18446744073709551615")
        )
        args = json.loads(plan["statements"][1]["params"][0])
        self.assertNotIn("start", args)
        self.assertEqual(args["id"], 18446744073709551615)
        self.assertIn(
            "audit_log_read_bookmark()",
            build_plan(dict(data, start_mode="bookmark"))["statements"][1]["sql"],
        )
        for size in [32767, 4194305, "nan"]:
            with self.assertRaises(ValueError):
                build_plan(dict(data, buffer_size=size))
        for timestamp in ["bad", "2026-02-30 00:00:00", "2026-10-26 00:00:00\x00"]:
            with self.assertRaises(ValueError):
                build_plan(dict(data, timestamp=timestamp))

    def test_filter_structure(self):
        obj = definition(
            dict(
                scope="rules",
                rules=[
                    dict(
                        **{"class": "general"},
                        events=["status"],
                        field="general_sql_command.str",
                        value="select",
                        enabled=True,
                    )
                ],
            )
        )
        self.assertFalse(obj["filter"]["log"])
        self.assertEqual(
            obj["filter"]["class"][0]["event"][0]["log"],
            {"field": {"name": "general_sql_command.str", "value": "select"}},
        )
        with self.assertRaises(ValueError):
            definition(dict(rules=[dict(**{"class": "general"}, events=["connect"])]))
        with self.assertRaises(ValueError):
            definition(dict(rules=[dict(**{"class": "general"}, events=[])]))
        with self.assertRaises(ValueError):
            definition(dict(mode="advanced", definition='{"filter":[]}'))

    def test_saved_view_uses_selected_buffer(self):
        plan = build_plan(
            {
                "action": "query_view",
                "database": "LogAnalytics",
                "view": "aud_view",
                "buffer_size": "65535",
            }
        )
        self.assertEqual(
            plan["statements"][0]["sql"], "SET SESSION audit_log_read_buffer_size = %s"
        )
        self.assertEqual(plan["statements"][0]["params"], (65535,))
        self.assertIn("SELECT * FROM", plan["statements"][1]["display"])
        with self.assertRaises(ValueError):
            build_plan(
                {"action": "query_view", "database": "LogAnalytics", "buffer_size": 1}
            )

    def test_rolling_reader_receives_json_text(self):
        plan = build_plan(
            {
                "action": "create_view",
                "database": "LogAnalytics",
                "view": "aud_view",
                "columns": ["ts"],
                "seconds": 90,
            }
        )
        sql = plan["statements"][0]["display"]
        self.assertIn("audit_log_read(CONCAT(", sql)
        self.assertNotIn("JSON_OBJECT", sql)
        self.assertIn("max_array_length", sql)

    def test_log_all_requires_no_class_rules(self):
        plan = build_plan(
            {"action": "save_filter", "name": "log_all", "scope": "all", "rules": []}
        )
        self.assertEqual(plan["definition"], {"filter": {"log": True}})
        self.assertNotIn("class", plan["definition"]["filter"])
        self.assertEqual(
            json.loads(plan["statements"][0]["params"][1]), {"filter": {"log": True}}
        )

    def test_numeric_filter_fields_use_numbers(self):
        rule = {
            "class": "connection",
            "events": ["connect"],
            "field": "status",
            "value": "0",
            "enabled": True,
        }
        obj = definition({"rules": [rule]})
        self.assertEqual(
            obj["filter"]["class"][0]["event"][0]["log"]["field"]["value"], 0
        )
        with self.assertRaises(ValueError):
            definition({"rules": [dict(rule, value="not-a-number")]})

    def test_view_sql_and_paths(self):
        data = dict(
            action="create_view",
            database="LogAnalytics",
            view="aud_view",
            columns=[c[0] for c in COLUMNS],
            timing="relative",
            seconds=90,
            max_events=500,
        )
        plan = build_plan(data)
        sql = plan["statements"][0]["sql"]
        display = plan["statements"][0]["display"]
        self.assertIn(
            "CREATE SQL SECURITY INVOKER VIEW `LogAnalytics`.`aud_view` AS", sql
        )
        self.assertIn("UTC_TIMESTAMP() - INTERVAL 90 SECOND", sql)
        self.assertIn("'%Y-%m-%d %H:%i:%s'", display)
        self.assertNotIn("@lastsec", sql)
        self.assertNotIn("DROP", sql)
        self.assertNotIn("OR REPLACE", sql)
        self.assertIn(
            "CREATE OR REPLACE",
            build_plan(dict(data, replace=True))["statements"][0]["sql"],
        )
        for path in [
            "$.connection_data.status",
            "$.connection_data.connection_type",
            "$.connection_data.connection_attributes._client_name",
            "$.general_data.status",
        ]:
            self.assertIn(path, sql)
        self.assertIn("`tsid` BIGINT UNSIGNED", sql)
        self.assertIn("NULL ON EMPTY NULL ON ERROR", sql)
        for bad in ["x`; DROP DATABASE x; --", "schema.name", ""]:
            with self.assertRaises(ValueError):
                build_plan(dict(data, database=bad))
        for bad in [[], ["unknown"], ["ts", "ts"]]:
            with self.assertRaises(ValueError):
                build_plan(dict(data, columns=bad))
        with self.assertRaises(ValueError):
            build_plan(dict(data, timing="next"))

    def test_bound_values_never_become_sql(self):
        evil = "name'); DROP DATABASE x; --\\\x00\n\r\x1a"
        plan = build_plan(
            dict(action="save_filter", name=evil.replace("\x00", ""), scope="all")
        )
        self.assertNotIn("DROP DATABASE", plan["statements"][0]["sql"])
        self.assertNotIn("DROP DATABASE", plan["statements"][0]["display"])
        for value in ["'", "\\", "\x00", "\n", "\r", "\x1a", "é"]:
            literal = sql_literal(value)
            if literal.startswith("CONVERT"):
                hexvalue = literal.split("'")[1]
                self.assertEqual(bytes.fromhex(hexvalue).decode(), value)
            else:
                self.assertEqual(literal[1:-1].replace("''", "'"), value)
        self.assertEqual(sql_literal(None), "NULL")
        self.assertEqual(escape_sql_literal(None), "NULL")


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "PROFILE_STORE": str(Path(self.temp.name) / "profiles.json"),
                "SECRET_KEY": "testing-secret",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def csrf(self):
        self.client.get("/login")
        with self.client.session_transaction() as cookie:
            sid = cookie["sid"]
        return self.app.extensions["audit_sessions"][sid]["csrf"]

    def demo(self):
        self.client.post("/login", data={"csrf": self.csrf(), "intent": "demo"})
        with self.client.session_transaction() as cookie:
            sid = cookie["sid"]
        self.rec = self.app.extensions["audit_sessions"][sid]
        return self.rec["csrf"]

    def test_private_configuration_overrides_defaults(self):
        config = Path(self.temp.name) / "private.json"
        config.write_text(
            json.dumps(
                {
                    "DEMO_ENABLED": False,
                    "SESSION_TTL": 120,
                    "SECRET_KEY": "private-test-key",
                }
            )
        )
        with patch.dict("os.environ", {"AUDIT_CONFIG_FILE": str(config)}):
            configured = create_app({"TESTING": True})
        self.assertFalse(configured.config["DEMO_ENABLED"])
        self.assertEqual(configured.config["SESSION_TTL"], 120)

    def test_auth_csrf_and_cookie(self):
        self.assertEqual(self.client.get("/reader").status_code, 302)
        self.assertEqual(
            self.client.post("/api/preview", json={"action": "inspect"}).status_code,
            400,
        )
        self.demo()
        with self.client.session_transaction() as cookie:
            self.assertEqual(set(cookie), {"sid"})
            self.assertNotIn("Sample user", str(dict(cookie)))
            self.app.extensions["audit_sessions"].pop(cookie["sid"])
        self.assertEqual(self.client.get("/filters").status_code, 302)

    def test_pages_and_sequence(self):
        csrf = self.demo()
        headers = {"X-CSRF-Token": csrf}
        for page in ["filters", "reader", "analytics"]:
            res = self.client.get("/" + page)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Sample workspace", res.data)

        def execute(data):
            response = self.client.post("/api/preview", json=data, headers=headers)
            self.assertEqual(response.status_code, 200, response.json)
            return self.client.post(
                "/api/execute", json={"token": response.json["token"]}, headers=headers
            )

        self.assertEqual(execute({"action": "next"}).status_code, 400)
        self.assertEqual(
            execute({"action": "read", "start_mode": "bookmark"}).status_code, 200
        )
        self.assertEqual(execute({"action": "next"}).status_code, 200)
        self.assertEqual(execute({"action": "close"}).status_code, 200)
        self.assertEqual(execute({"action": "next"}).status_code, 400)
        self.assertEqual(
            execute(
                {"action": "save_filter", "name": "audit_test", "scope": "all"}
            ).status_code,
            200,
        )
        self.assertEqual(
            execute(
                {"action": "assign", "name": "audit_test", "account": "user@%"}
            ).status_code,
            200,
        )
        self.assertEqual(execute({"action": "databases"}).status_code, 200)
        self.assertEqual(
            execute(
                {
                    "action": "create_view",
                    "database": "LogAnalytics",
                    "view": "aud_view",
                    "columns": ["ts", "class", "query"],
                    "timing": "relative",
                    "seconds": 90,
                }
            ).status_code,
            200,
        )
        res = execute(
            {"action": "query_view", "database": "LogAnalytics", "view": "aud_view"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["results"][0]["columns"], ["ts", "class", "query"])

    def test_preview_is_single_use_and_session_bound(self):
        csrf = self.demo()
        headers = {"X-CSRF-Token": csrf}
        preview = self.client.post(
            "/api/preview", json={"action": "inspect"}, headers=headers
        ).json
        other = self.app.test_client()
        other.get("/login")
        self.assertEqual(
            other.post(
                "/api/execute", json={"token": preview["token"]}, headers=headers
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/execute", json={"token": preview["token"]}, headers=headers
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/execute", json={"token": preview["token"]}, headers=headers
            ).status_code,
            400,
        )

    def test_live_login_keeps_password_server_side(self):
        connection = MagicMock()
        connection.cursor.return_value.fetchone.return_value = None
        with patch("app.open_connection", return_value=(connection, None)):
            res = self.client.post(
                "/login",
                data=dict(
                    csrf=self.csrf(),
                    intent="create",
                    name="test",
                    host="db.invalid",
                    port="3306",
                    ssl_mode="REQUIRED",
                    username="private-user",
                    password="sensitive-test-password",
                ),
            )
        self.assertEqual(res.status_code, 302)
        stored = Path(self.app.config["PROFILE_STORE"]).read_text()
        self.assertNotIn("sensitive-test-password", stored)
        self.assertNotIn("private-user", stored)
        with self.client.session_transaction() as cookie:
            self.assertEqual(set(cookie), {"sid"})
            self.assertNotIn("sensitive-test-password", str(dict(cookie)))
        self.assertNotIn(b"sensitive-test-password", self.client.get("/reader").data)
        csrf = self.app.extensions["audit_sessions"][cookie["sid"]]["csrf"]
        self.client.post("/logout", data={"csrf": csrf})
        connection.close.assert_called_once()

    def test_expiry_closes_connection(self):
        self.demo()
        conn = MagicMock()
        self.rec["connection"] = conn
        self.rec["expires"] = time.time() - 1
        self.client.get("/reader")
        conn.close.assert_called_once()

    def test_notifications_isolated(self):
        csrf = self.demo()
        self.rec["notifications"] = [
            {"message": "<script>", "category": "success", "time": "now"}
        ]
        self.assertEqual(
            self.client.get("/api/notifications").json["messages"][0]["message"],
            "<script>",
        )
        self.client.post(
            "/api/notifications/clear", json={}, headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(self.client.get("/api/notifications").json["messages"], [])


class ErrorTests(unittest.TestCase):
    def test_unknown_audit_reason_is_visible_with_redaction(self):
        from mysql.connector import Error

        from modules.errors import mysql_error_message

        exc = Error(
            msg="audit_log_read UDF failed; Cannot read '/private/secret/log'; access-key-123",
            errno=3200,
        )
        exc.audit_statement_index = 5
        exc.audit_statement_count = 5
        message = mysql_error_message(exc, ("access-key-123",))
        self.assertIn("Statement 5 of 5", message)
        self.assertIn("Cannot read", message)
        self.assertNotIn("/private/secret/log", message)
        self.assertNotIn("access-key-123", message)

    def test_reader_errors_are_actionable_and_do_not_echo_secrets(self):
        from mysql.connector import Error

        from modules.errors import mysql_error_message

        for reason, expected in [
            ("Reader not initialized", "Start a new read"),
            ("Wrong argument format", "JSON argument format"),
            ("requires JSON format", "requires JSON audit log format"),
        ]:
            error = Error(
                msg="audit_log_read UDF failed; " + reason + "; password=private-value",
                errno=3200,
            )
            explanation = mysql_error_message(error)
            self.assertIn(expected, explanation)
            self.assertNotIn("private-value", explanation)
        self.assertNotIn(
            "private-value", mysql_error_message(Error(msg="private-value", errno=3200))
        )


class ConnectorTests(unittest.TestCase):
    def test_tls(self):
        for mode in ["REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY", "DISABLED"]:
            args = build_tls_kwargs({"ssl_mode": mode, "ssl_ca": "ca.pem"})
            self.assertEqual(args["ssl_disabled"], mode == "DISABLED")
            if mode != "DISABLED":
                self.assertTrue(args["client_flags"])
            if mode in ["VERIFY_CA", "VERIFY_IDENTITY"]:
                self.assertTrue(args["ssl_verify_cert"])
            if mode == "VERIFY_IDENTITY":
                self.assertTrue(args["ssl_verify_identity"])

    def test_cache_reuse_and_health(self):
        connection = MagicMock()
        with patch(
            "modules.mysql_util.open_connection", return_value=(connection, None)
        ) as opened:
            cache = ConnectionCache()
            a = cache.borrow("id", {"host": "db.invalid"}, "u", "p")
            b = cache.borrow("id", {"host": "db.invalid"}, "u", "p")
            self.assertIs(a, b)
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(connection.cursor.return_value.execute.call_count, 2)
            cache.close("id")
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
