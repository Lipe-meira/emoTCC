"""SQLite schema: immutable references separated from replay state."""
import json
import sqlite3


def connect(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.execute('PRAGMA cache_size=-32768')
    return db


def initialize(db, features):
    columns = ','.join(f'"{name}" REAL NOT NULL' for name in features)
    db.executescript(f'''
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE events (
      event_id TEXT PRIMARY KEY, label TEXT NOT NULL, group_key TEXT NOT NULL,
      source TEXT NOT NULL, source_row INTEGER NOT NULL,
      source_timestamp TEXT, time_order INTEGER, split_key TEXT NOT NULL,
      conflict INTEGER NOT NULL DEFAULT 0, split TEXT NOT NULL DEFAULT 'pending',
      {columns});
    CREATE TABLE duplicates (
      event_id TEXT NOT NULL REFERENCES events(event_id), source TEXT NOT NULL,
      source_row INTEGER NOT NULL, label TEXT NOT NULL);
    CREATE TABLE profiles (profile_id TEXT PRIMARY KEY, observations INTEGER NOT NULL,
      active INTEGER NOT NULL, payload TEXT NOT NULL);
    CREATE TABLE decisions (
      run_id TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES events(event_id),
      detector TEXT NOT NULL CHECK(detector IN ('A','B')), sequence INTEGER NOT NULL,
      profile_id TEXT NOT NULL REFERENCES profiles(profile_id), profile_status TEXT NOT NULL,
      suspicious INTEGER NOT NULL, rules_evaluated INTEGER NOT NULL,
      alert_count INTEGER NOT NULL, detection_seconds REAL NOT NULL,
      PRIMARY KEY(run_id,event_id,detector));
    CREATE TABLE alerts (
      run_id TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES events(event_id),
      detector TEXT NOT NULL, rule TEXT NOT NULL, feature TEXT NOT NULL,
      observed REAL, threshold REAL, profile_id TEXT NOT NULL REFERENCES profiles(profile_id),
      reason TEXT NOT NULL);
    CREATE TABLE operational_state (
      group_key TEXT PRIMARY KEY, processed_events INTEGER NOT NULL,
      last_event_id TEXT NOT NULL, last_timestamp TEXT);
    ''')
    db.commit()


def put_meta(db, key, value):
    db.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)',
               (key, json.dumps(value, ensure_ascii=False, allow_nan=False)))


def get_meta(db, key):
    row = db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else None
