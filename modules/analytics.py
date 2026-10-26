"""Documented MySQL Enterprise Audit JSON columns and visual view builder."""

import json
import re

from modules.audit import integer, sql_literal, statement, timestamp

# name, SQL type, JSON path, event class
COLUMNS = [
    ("ts", "DATETIME", "$.timestamp", "All"),
    ("tsid", "BIGINT UNSIGNED", "$.id", "All"),
    ("class", "VARCHAR(20)", "$.class", "All"),
    ("event", "VARCHAR(80)", "$.event", "All"),
    ("login_ip", "VARCHAR(200)", "$.login.ip", "All"),
    ("login_user", "VARCHAR(200)", "$.login.user", "All"),
    ("account_user", "VARCHAR(200)", "$.account.user", "All"),
    ("account_host", "VARCHAR(255)", "$.account.host", "All"),
    ("connection_id", "BIGINT UNSIGNED", "$.connection_id", "All"),
    ("status", "INT", "$.connection_data.status", "Connection"),
    (
        "connection_type",
        "VARCHAR(40)",
        "$.connection_data.connection_type",
        "Connection",
    ),
    (
        "c_client_name",
        "VARCHAR(128)",
        "$.connection_data.connection_attributes._client_name",
        "Connection",
    ),
    (
        "c_client_version",
        "VARCHAR(128)",
        "$.connection_data.connection_attributes._client_version",
        "Connection",
    ),
    ("command", "VARCHAR(80)", "$.general_data.command", "General"),
    ("sql_command", "VARCHAR(80)", "$.general_data.sql_command", "General"),
    ("command_status", "INT", "$.general_data.status", "General"),
    ("query", "TEXT", "$.general_data.query", "General"),
    ("table_database", "VARCHAR(255)", "$.table_access_data.db", "Table access"),
    ("table_name", "VARCHAR(255)", "$.table_access_data.table", "Table access"),
    ("table_query", "TEXT", "$.table_access_data.query", "Table access"),
    (
        "table_sql_command",
        "VARCHAR(80)",
        "$.table_access_data.sql_command",
        "Table access",
    ),
]


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,63}", value
    ):
        raise ValueError(
            "Database and view names must start with a letter or underscore and use up to 64 letters, numbers or underscores."
        )
    return "`" + value + "`"


def analytics_plan(data):
    action = data["action"]
    if action == "databases":
        return {"action": action, "statements": [statement("SHOW DATABASES")]}
    db = identifier(data.get("database", ""))
    if action == "create_database":
        return {
            "action": action,
            "statements": [
                statement(f"CREATE DATABASE IF NOT EXISTS {db} CHARACTER SET utf8mb4")
            ],
        }
    view = identifier(data.get("view", "aud_view"))
    if action == "query_view":
        return {
            "action": action,
            "statements": [
                statement(
                    "SET SESSION audit_log_read_buffer_size = %s",
                    integer(
                        data.get("buffer_size", 32768),
                        32768,
                        4194304,
                        "Read buffer size",
                    ),
                ),
                statement(f"SELECT * FROM {db}.{view} LIMIT 1000"),
            ],
        }
    if action not in ("create_view", "analytics_query"):
        raise ValueError("Unknown analytics action.")
    selected = data.get("columns", [])
    if (
        not isinstance(selected, list)
        or not selected
        or len(set(selected)) != len(selected)
    ):
        raise ValueError("Select at least one unique column.")
    specs = {c[0]: c for c in COLUMNS}
    if any(c not in specs for c in selected):
        raise ValueError("Unknown audit column.")
    mode = data.get("timing", "relative")
    count = integer(data.get("max_events", 500), 1, 10000, "Maximum events")
    if mode == "relative":
        seconds = integer(data.get("seconds", 90), 1, 604800, "Lookback seconds")
        # Pass JSON text, matching Oracle's audit_log_read examples, rather than
        # relying on conversion of native JSON values at the UDF boundary.
        prefix = 'CONCAT(\'{"start":{"timestamp":"\', '
        suffix = '\'"},"max_array_length":'
        arg = (
            prefix
            + f"DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL {seconds} SECOND, '%Y-%m-%d %H:%i:%s'), "
            + suffix
            + str(count)
            + "}')"
        )
    elif mode == "timestamp":
        arg = sql_literal(
            json.dumps(
                {
                    "start": {"timestamp": timestamp(data.get("timestamp"))},
                    "max_array_length": count,
                }
            )
        )
    elif mode == "next" and action == "analytics_query":
        arg = sql_literal(json.dumps({"max_array_length": count}))
    else:
        raise ValueError(
            "Choose a rolling time window or a fixed timestamp for a view."
        )
    fields = ",\n    ".join(
        f"`{name}` {specs[name][1]} PATH '{specs[name][2]}' NULL ON EMPTY NULL ON ERROR"
        for name in selected
    )
    projection = ", ".join("audit_log.`" + name + "`" for name in selected)
    sql = f"SELECT {projection}\nFROM JSON_TABLE(\n  CONVERT(audit_log_read({arg}) USING utf8mb4),\n  '$[*]' COLUMNS (\n    {fields}\n  )\n) AS audit_log\nWHERE audit_log.`{selected[0]}` IS NOT NULL"
    # Exclude the reader's JSON null end-of-stream marker via FOR ORDINALITY-independent sentinel.
    # Use a hidden existence column instead of a selected field that may be absent in some classes.
    sql = sql.replace(
        fields, "`_audit_exists` INT EXISTS PATH '$.timestamp',\n    " + fields
    ).replace(
        f"WHERE audit_log.`{selected[0]}` IS NOT NULL",
        "WHERE audit_log.`_audit_exists` = 1",
    )
    statements = []
    if action == "create_view":
        # Do not drop an existing view before a new definition has passed server validation.
        prefix = "CREATE OR REPLACE" if data.get("replace") is True else "CREATE"
        statements.append(
            statement(f"{prefix} SQL SECURITY INVOKER VIEW {db}.{view} AS\n" + sql)
        )
    else:
        size = integer(
            data.get("buffer_size", 32768), 32768, 4194304, "Read buffer size"
        )
        statements.extend(
            [
                statement("SET SESSION audit_log_read_buffer_size = %s", size),
                statement(sql),
            ]
        )
    return {
        "action": action,
        "statements": statements,
        "columns": selected,
        "timing": mode,
    }
