"""Deterministic, labeled sample results; never connects or executes SQL."""

import json
from datetime import datetime, timezone


def sample_events():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    common = dict(
        timestamp=ts,
        connection_id=42,
        account={"user": "demo", "host": "%"},
        login={"user": "demo", "ip": "sample-client"},
    )
    return [
        dict(
            common,
            id=0,
            **{"class": "connection"},
            event="connect",
            connection_data={
                "connection_type": "ssl",
                "status": 0,
                "connection_attributes": {
                    "_client_name": "sample-client",
                    "_client_version": "1.0",
                },
            },
        ),
        dict(
            common,
            id=1,
            **{"class": "general"},
            event="status",
            general_data={
                "command": "Query",
                "sql_command": "select",
                "status": 0,
                "query": "SELECT * FROM sample_orders",
            },
        ),
        dict(
            common,
            id=2,
            **{"class": "table_access"},
            event="read",
            table_access_data={
                "db": "sample_sales",
                "table": "sample_orders",
                "sql_command": "select",
                "query": "SELECT * FROM sample_orders",
            },
        ),
    ]


def demo_execute(rec, plan):
    action = plan["action"]
    result = [{"result": "OK (sample)"}]
    if action == "save_filter":
        rec.setdefault("demo_filters", {})[plan["statements"][0]["params"][0]] = plan[
            "definition"
        ]
    elif action == "assign":
        account, name = plan["statements"][0]["params"]
        if name not in rec.get("demo_filters", {}):
            raise ValueError("Save that filter in this sample workspace first.")
        rec.setdefault("demo_assignments", {})[account] = name
    elif action == "unassign":
        rec.setdefault("demo_assignments", {}).pop(
            plan["statements"][0]["params"][0], None
        )
    elif action == "list_filters":
        filters = [
            {"name": k, "definition": json.dumps(v)}
            for k, v in rec.get("demo_filters", {}).items()
        ]
        users = [
            {
                "user": k.rsplit("@", 1)[0],
                "host": k.rsplit("@", 1)[-1] if "@" in k else "",
                "filter_name": v,
            }
            for k, v in rec.get("demo_assignments", {}).items()
        ]
        return {
            "results": [
                {"columns": ["name", "definition"], "rows": filters},
                {"columns": ["user", "host", "filter_name"], "rows": users},
            ],
            "warnings": [],
        }
    elif action == "inspect":
        result = [
            {"Variable_name": "audit_log_format", "Value": "JSON"},
            {"Variable_name": "audit_log_database", "Value": "mysql_audit"},
            {"Variable_name": "audit_log_read_buffer_size", "Value": "32768"},
        ]
    elif action == "bookmark":
        result = [
            {
                "bookmark": json.dumps(
                    {k: sample_events()[0][k] for k in ("timestamp", "id")}
                )
            }
        ]
    elif action in ("read", "next"):
        result = [{"events": json.dumps(sample_events() + [None])}]
    elif action == "close":
        result = [{"events": "null"}]
    elif action == "databases":
        result = [
            {"Database": name}
            for name in ["LogAnalytics", "sample_sales"] + rec.get("demo_databases", [])
        ]
    elif action == "create_database":
        name = plan["statements"][0]["sql"].split("`")[1]
        if name not in rec.setdefault("demo_databases", []):
            rec["demo_databases"].append(name)
    elif action == "create_view":
        rec["demo_view_columns"] = plan["columns"]
    elif action in ("analytics_query", "query_view"):
        from modules.analytics import COLUMNS

        specs = {c[0]: c[2] for c in COLUMNS}
        selected = plan.get("columns", rec.get("demo_view_columns", []))
        if not selected:
            raise ValueError("Create a sample view first.")
        result = []
        for event in sample_events():
            row = {}
            for name in selected:
                value = event
                for part in specs[name][2:].split("."):
                    value = value.get(part) if isinstance(value, dict) else None
                row[name] = value
            result.append(row)
    return {
        "results": [{"columns": list(result[0]) if result else [], "rows": result}],
        "warnings": [],
    }
