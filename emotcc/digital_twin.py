"""Public reference API. Replay never writes the reference profiles."""
from array import array
import json
from time import perf_counter
from .database import get_meta


class DigitalTwin:
    def __init__(self, db):
        self.db = db
        self.cache = {}
        self.query_seconds = array('d')
        self.sql_queries = 0
        self.groups = {row[0] for row in db.execute("SELECT profile_id FROM profiles WHERE profile_id!='global'")}
        self.global_profile = self._load('global')
        if self.global_profile is None:
            raise ValueError('Perfil global ausente; execute build primeiro.')

    def _load(self, key):
        row = self.db.execute('SELECT payload FROM profiles WHERE profile_id=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def lookup(self, group_key):
        start = perf_counter()
        row = self.db.execute('SELECT active FROM profiles WHERE profile_id=?', (group_key,)).fetchone()
        self.sql_queries += 1
        if row and row[0]:
            if group_key not in self.cache:
                self.cache[group_key] = self._load(group_key)
                self.sql_queries += 1
            result = self.cache[group_key], 'specific'
        else:
            result = self.global_profile, 'sparse_global' if row else 'unseen_global'
        self.query_seconds.append(perf_counter() - start)
        return result
