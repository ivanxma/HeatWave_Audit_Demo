"""Validated audit operations: SQL preview and execution share a single plan."""

import json
from datetime import datetime

CLASSES = {
    "connection": {
        "events": ["connect", "change_user", "disconnect"],
        "fields": ["status", "user.str", "host.str", "ip.str"],
    },
    "general": {
        "events": ["status"],
        "fields": [
            "general_sql_command.str",
            "general_error_code",
            "general_query.str",
        ],
    },
    "table_access": {
        "events": ["read", "insert", "update", "delete"],
        "fields": ["table_database.str", "table_name.str"],
    },
    "message": {"events": ["internal", "user"], "fields": []},
}
MIN_BUFFER, MAX_BUFFER = 32768, 4194304


def integer(value, low, high, label):
    try:
        if isinstance(value, bool):
            raise ValueError()
        n = int(str(value))
    except (ValueError, TypeError):
        raise ValueError(f"{label} must be an integer.") from None
    if not low <= n <= high:
        raise ValueError(f"{label} must be between {low} and {high}.")
    return n


def text(value, label, maximum=255):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{label} is required (maximum {maximum} characters).")
    return value.strip()


def timestamp(value):
    value = text(value, "Timestamp").replace("T", " ")
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError(
            "Use a timestamp in YYYY-MM-DD HH:MM:SS format, in the audit log time zone."
        ) from None
    return value


def definition(data):
    if data.get("mode") == "advanced":
        try:
            obj = json.loads(data.get("definition", ""))
        except (ValueError, TypeError):
            raise ValueError("The advanced definition must be valid JSON.") from None
        if not isinstance(obj, dict) or not isinstance(obj.get("filter"), dict):
            raise ValueError(
                "JSON must contain a filter object. MySQL validates the complete filter grammar on execution."
            )
        return obj
    scope = data.get("scope", "rules")
    if scope in ("all", "none"):
        return {"filter": {"log": scope == "all"}}
    rules = data.get("rules", [])
    if not isinstance(rules, list) or not 1 <= len(rules) <= 20:
        raise ValueError("Add between 1 and 20 class rules.")
    classes, seen = [], set()
    for rule in rules:
        name = rule.get("class")
        if name not in CLASSES or name in seen:
            raise ValueError("Choose each class at most once.")
        seen.add(name)
        enabled = rule.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("Log enabled must be true or false.")
        match = enabled
        field = rule.get("field", "")
        if field:
            if field not in CLASSES[name]["fields"]:
                raise ValueError("The matching field does not belong to this class.")
            value = text(rule.get("value"), "Match value", 2048)
            # Match the documented integer type for status/error fields.
            if field in {"status", "general_error_code"}:
                value = integer(value, 0, 2147483647, "Match value")
            match = {"field": {"name": field, "value": value}} if enabled else False
        events = rule.get("events", [])
        if not isinstance(events, list) or any(
            e not in CLASSES[name]["events"] for e in events
        ):
            raise ValueError("Unsupported event subclass.")
        if enabled and not events:
            raise ValueError(
                "Select at least one event subclass for each enabled class rule."
            )
        item = {"name": name}
        if events:
            item["event"] = [{"name": e, "log": match} for e in events]
        else:
            item["log"] = False
        classes.append(item)
    return {"filter": {"log": False, "class": classes}}


def sql_literal(value):
    # Prefer readable literals; use UTF-8 hex for backslashes/control characters.
    # Doubling single quotes is supported with and without NO_BACKSLASH_ESCAPES.
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    value = str(value)
    if "\\" not in value and not any(ord(c) < 32 for c in value):
        return "'" + value.replace("'", "''") + "'"
    return "CONVERT(X'" + str(value).encode("utf-8").hex() + "' USING utf8mb4)"


def statement(sql, *params):
    parts = sql.split("%s", len(params))
    display = parts[0]
    for value, part in zip(params, parts[1:]):
        display += sql_literal(value) + part
    return {"sql": sql, "params": params, "display": display + ";"}


def build_plan(data, audit_database="mysql_audit"):
    action = data.get("action")
    if action in (
        "databases",
        "create_database",
        "create_view",
        "analytics_query",
        "query_view",
    ):
        from modules.analytics import analytics_plan

        return analytics_plan(data)
    schema = "`" + audit_database.replace("`", "``") + "`"
    info = {}
    if action == "save_filter":
        obj = definition(data)
        name = text(data.get("name"), "Filter name", 64)
        payload = json.dumps(obj, ensure_ascii=False)
        statements = [
            statement(
                "SELECT audit_log_filter_set_filter(%s, %s) AS result", name, payload
            )
        ]
        info["definition"] = obj
    elif action in ("assign", "unassign"):
        account = text(data.get("account"), "Account")
        if account != "%" and ("@" not in account or not all(account.rsplit("@", 1))):
            raise ValueError("Use user@host, or % for the default account.")
        if action == "assign":
            statements = [
                statement(
                    "SELECT audit_log_filter_set_user(%s, %s) AS result",
                    account,
                    text(data.get("name"), "Filter name", 64),
                )
            ]
        else:
            statements = [
                statement("SELECT audit_log_filter_remove_user(%s) AS result", account)
            ]
    elif action == "inspect":
        statements = [statement("SHOW VARIABLES LIKE 'audit_log%'")]
    elif action == "list_filters":
        statements = [
            statement(
                f"SELECT NAME AS name, FILTER AS definition FROM {schema}.audit_log_filter ORDER BY NAME"
            ),
            statement(
                f"SELECT USER AS user, HOST AS host, FILTERNAME AS filter_name FROM {schema}.audit_log_user ORDER BY USER, HOST"
            ),
        ]
    elif action == "bookmark":
        statements = [statement("SELECT audit_log_read_bookmark() AS bookmark")]
    elif action == "close":
        statements = [statement("SELECT audit_log_read('null') AS events")]
    elif action in ("read", "next"):
        size = integer(
            data.get("buffer_size", MIN_BUFFER),
            MIN_BUFFER,
            MAX_BUFFER,
            "Read buffer size",
        )
        count = integer(data.get("max_events", 100), 1, 10000, "Maximum events")
        args = {"max_array_length": count}
        mode = data.get("start_mode", "bookmark")
        if action == "next":
            mode = "next"
        if mode == "timestamp":
            args["start"] = {"timestamp": timestamp(data.get("timestamp"))}
        elif mode == "position":
            args.update(
                timestamp=timestamp(data.get("timestamp")),
                id=integer(data.get("event_id"), 0, 18446744073709551615, "Event ID"),
            )
        elif mode not in ("bookmark", "next"):
            raise ValueError("Choose a supported starting position.")
        statements = [statement("SET SESSION audit_log_read_buffer_size = %s", size)]
        if mode == "bookmark":
            # Follow the manual's separate bookmark/JSON_SET/read sequence.
            # Explicit text conversions also handle binary bookmark results.
            statements.extend(
                [
                    statement(
                        "SET @audit_reader_bookmark = CONVERT(audit_log_read_bookmark() USING utf8mb4)"
                    ),
                    statement(
                        "SET @audit_reader_args = CONVERT(JSON_SET(@audit_reader_bookmark, '$.max_array_length', %s) USING utf8mb4)",
                        count,
                    ),
                    statement("SELECT @audit_reader_args AS reader_arguments"),
                    statement("SELECT audit_log_read(@audit_reader_args) AS events"),
                ]
            )
        else:
            statements.append(
                statement("SELECT audit_log_read(%s) AS events", json.dumps(args))
            )
        info["reader_mode"] = mode
    else:
        raise ValueError("Unsupported audit operation.")
    return {"action": action, "statements": statements, **info}


def execute_plan(connection, plan):
    results, warnings = [], []
    for statement_index, item in enumerate(plan["statements"], start=1):
        cursor = connection.cursor(dictionary=True, buffered=True)
        try:
            cursor.execute(item["sql"], item["params"])
            while True:
                if cursor.with_rows:
                    rows = cursor.fetchall()
                    for row in rows:
                        for key, value in list(row.items()):
                            if isinstance(value, bytes):
                                row[key] = value.decode("utf-8", errors="replace")
                        if str(row.get("result", "")).startswith("ERROR"):
                            raise ValueError(
                                "The audit function rejected the operation. Check filter syntax, account and privileges."
                            )
                    results.append(
                        {
                            "columns": list(rows[0])
                            if rows
                            else list(cursor.column_names),
                            "rows": rows,
                        }
                    )
                if not cursor.nextset():
                    break
        except Exception as exc:
            # Keep the connector exception's errno/message while adding context.
            exc.audit_statement_index = statement_index
            exc.audit_statement_count = len(plan["statements"])
            raise
        finally:
            cursor.close()
        cursor = connection.cursor(dictionary=True, buffered=True)
        try:
            cursor.execute("SHOW WARNINGS")
            # Keep codes; avoid echoing server text that might contain sensitive data.
            warnings.extend(
                {"level": r.get("Level"), "code": r.get("Code")}
                for r in cursor.fetchall()
            )
        finally:
            cursor.close()
    return {"results": results, "warnings": warnings}
