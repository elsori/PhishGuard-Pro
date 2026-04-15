#!/usr/bin/env python3
"""
PhishGuard Pro - Client and Scan Database Manager
Manages SQLite database for clients and their email scans.
"""

import sqlite3
import json
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any


class ClientDB:
    """SQLite database manager for clients and scans."""

    def __init__(self, db_path: Path):
        """Initialize database connection and create tables if needed."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_db()

    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database tables if they don't exist."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Create clients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                company TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                sector TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                risk_score INTEGER,
                verdict TEXT,
                risk_level TEXT,
                flags_count INTEGER,
                analysis_json TEXT,
                notes TEXT,
                FOREIGN KEY (client_id) REFERENCES clients (id)
            )
        ''')

        conn.commit()
        conn.close()

    def add_client(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new client."""
        client_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO clients (id, name, company, email, phone, sector, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            data.get('name', ''),
            data.get('company', ''),
            data.get('email', ''),
            data.get('phone', ''),
            data.get('sector', ''),
            data.get('notes', ''),
            now,
            now
        ))

        conn.commit()
        conn.close()

        return self.get_client(client_id)

    def get_clients(self) -> List[Dict[str, Any]]:
        """Get all clients."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM clients ORDER BY updated_at DESC')
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_dict(row) for row in rows]

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get a single client by ID."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM clients WHERE id = ?', (client_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return self._row_to_dict(row)

    def update_client(self, client_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a client."""
        conn = self._get_conn()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()

        # Build update query dynamically
        fields = []
        values = []
        for key in ['name', 'company', 'email', 'phone', 'sector', 'notes']:
            if key in data:
                fields.append(f"{key} = ?")
                values.append(data[key])

        if not fields:
            conn.close()
            return self.get_client(client_id)

        fields.append("updated_at = ?")
        values.append(now)
        values.append(client_id)

        query = f"UPDATE clients SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, values)
        conn.commit()
        conn.close()

        return self.get_client(client_id)

    def delete_client(self, client_id: str) -> bool:
        """Delete a client and all their scans."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Delete scans first
        cursor.execute('DELETE FROM scans WHERE client_id = ?', (client_id,))
        # Delete client
        cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))

        conn.commit()
        conn.close()

        return True

    def add_scan(self, client_id: str, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add a scan from analysis data."""
        scan_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Extract data from analysis dict
        parsed_headers = analysis.get('parsed_headers', {})
        risk = analysis.get('risk', {})

        subject = ''
        if isinstance(parsed_headers.get('Subject'), list):
            subject = parsed_headers['Subject'][0] if parsed_headers['Subject'] else ''
        else:
            subject = parsed_headers.get('Subject', '')

        sender = ''
        if isinstance(parsed_headers.get('From'), list):
            sender = parsed_headers['From'][0] if parsed_headers['From'] else ''
        else:
            sender = parsed_headers.get('From', '')

        risk_score = risk.get('score', 0)
        verdict = risk.get('verdict', 'Unknown')
        risk_level = risk.get('risk_level', 'unknown')

        # Count flags
        flags = analysis.get('flags', [])
        flags_count = len(flags) if isinstance(flags, list) else 0

        # Compress analysis JSON
        analysis_json = json.dumps(analysis, ensure_ascii=False, separators=(',', ':'))

        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scans (id, client_id, timestamp, subject, sender, risk_score, verdict, risk_level, flags_count, analysis_json, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            client_id,
            now,
            subject,
            sender,
            risk_score,
            verdict,
            risk_level,
            flags_count,
            analysis_json,
            ''
        ))

        conn.commit()
        conn.close()

        return self.get_scan(scan_id)

    def get_scans(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scans, optionally filtered by client."""
        conn = self._get_conn()
        cursor = conn.cursor()

        if client_id:
            cursor.execute('SELECT * FROM scans WHERE client_id = ? ORDER BY timestamp DESC', (client_id,))
        else:
            cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC')

        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_dict(row) for row in rows]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single scan by ID."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        scan_dict = self._row_to_dict(row)

        # Decompress analysis_json
        if scan_dict.get('analysis_json'):
            try:
                scan_dict['analysis'] = json.loads(scan_dict['analysis_json'])
                del scan_dict['analysis_json']
            except json.JSONDecodeError:
                scan_dict['analysis'] = {}

        return scan_dict

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()

        return True

    def get_client_stats(self, client_id: str) -> Dict[str, Any]:
        """Get statistics for a client."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COUNT(*) as total_scans,
                   AVG(risk_score) as avg_score,
                   MAX(timestamp) as last_scan,
                   SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) as phishing_count,
                   SUM(CASE WHEN risk_score < 30 THEN 1 ELSE 0 END) as clean_count
            FROM scans WHERE client_id = ?
        ''', (client_id,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return {
                'total_scans': 0,
                'avg_score': 0,
                'last_scan': None,
                'phishing_count': 0,
                'clean_count': 0
            }

        return {
            'total_scans': row['total_scans'] or 0,
            'avg_score': round(row['avg_score'] or 0, 1),
            'last_scan': row['last_scan'],
            'phishing_count': row['phishing_count'] or 0,
            'clean_count': row['clean_count'] or 0
        }

    def search_clients(self, query: str) -> List[Dict[str, Any]]:
        """Search clients by name, company, or email."""
        conn = self._get_conn()
        cursor = conn.cursor()

        q = f"%{query}%"
        cursor.execute('''
            SELECT * FROM clients
            WHERE name LIKE ? OR company LIKE ? OR email LIKE ?
            ORDER BY updated_at DESC
        ''', (q, q, q))

        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """Convert sqlite3.Row to dict."""
        return dict(row)
