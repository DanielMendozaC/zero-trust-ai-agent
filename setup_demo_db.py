"""
Sets up a local SQLite database with sample data for demonstrating
the Zero Trust AI Agent's database query security controls.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "demo.db")


def setup_database():
    """Create demo database with sample tables and data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Employees table (non-sensitive)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL,
            hire_date TEXT NOT NULL
        )
    """)

    # Projects table (non-sensitive)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            lead_id INTEGER,
            budget REAL,
            FOREIGN KEY (lead_id) REFERENCES employees(id)
        )
    """)

    # Credentials table (sensitive - should be blocked by risk scoring)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_credentials (
            id INTEGER PRIMARY KEY,
            service_name TEXT NOT NULL,
            api_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Audit events table (sensitive)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    # Insert sample data
    cursor.executemany(
        "INSERT OR IGNORE INTO employees VALUES (?, ?, ?, ?, ?)",
        [
            (1, "Alice Chen", "Engineering", "Senior Engineer", "2023-01-15"),
            (2, "Bob Martinez", "Engineering", "Tech Lead", "2022-06-01"),
            (3, "Carol Williams", "Security", "Security Analyst", "2023-03-20"),
            (4, "David Kim", "Data Science", "ML Engineer", "2024-01-10"),
            (5, "Eva Patel", "Engineering", "DevOps Engineer", "2023-09-05"),
        ],
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO projects VALUES (?, ?, ?, ?, ?)",
        [
            (1, "AI Agent Platform", "active", 2, 500000.0),
            (2, "Security Monitoring", "active", 3, 250000.0),
            (3, "Data Pipeline v2", "planning", 4, 180000.0),
        ],
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO api_credentials VALUES (?, ?, ?, ?)",
        [
            (1, "OpenAI", "sk-fake-key-12345", "2024-01-01"),
            (2, "AWS", "AKIA-FAKE-KEY-67890", "2024-02-15"),
            (3, "Stripe", "sk_test_fake_key", "2024-03-01"),
        ],
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO security_events VALUES (?, ?, ?, ?, ?)",
        [
            (1, "login_failure", "medium", "3 failed login attempts from IP 192.168.1.50", "2025-10-01T08:30:00"),
            (2, "privilege_escalation", "high", "Unauthorized admin access attempt", "2025-10-02T14:15:00"),
            (3, "data_export", "low", "Scheduled report exported successfully", "2025-10-03T09:00:00"),
        ],
    )

    conn.commit()
    conn.close()
    print(f"Demo database created at {DB_PATH}")
    print("Tables: employees, projects, api_credentials, security_events")


if __name__ == "__main__":
    setup_database()
