"""Assign each unique observable vector to exactly one experimental partition."""
import math
from .database import put_meta


def split_dataset(db, cfg):
    db.execute("UPDATE events SET split=CASE WHEN conflict=1 THEN 'excluded' ELSE 'test' END")
    benign = db.execute("SELECT count(*) FROM events WHERE conflict=0 AND label='BENIGN'").fetchone()[0]
    count = math.floor(benign * cfg.train_fraction)
    if count < cfg.min_profile_samples or benign - count < 1:
        raise ValueError(f'Tráfego benigno insuficiente: {benign}; construção={count}; mínimo={cfg.min_profile_samples}.')
    order = 'time_order,source,source_row,event_id' if cfg.timestamp_format else 'split_key,event_id'
    db.execute(f'''UPDATE events SET split='build' WHERE event_id IN (
        SELECT event_id FROM events WHERE conflict=0 AND label='BENIGN' ORDER BY {order} LIMIT ?)''', (count,))
    db.execute('CREATE INDEX IF NOT EXISTS events_split ON events(split,group_key)')
    assert db.execute("SELECT count(*) FROM events WHERE split='build' AND (label!='BENIGN' OR conflict=1)").fetchone()[0] == 0
    summary = {'benign_unique': benign, 'build': count,
               'test_benign': benign - count, 'method': 'chronological' if cfg.timestamp_format else 'seeded_hash_rank',
               'overlapping_vectors': 0, 'seed': cfg.seed,
               'classes': [dict(zip(['split','label','count'], r)) for r in
                           db.execute('SELECT split,label,count(*) FROM events GROUP BY split,label ORDER BY split,label')]}
    put_meta(db, 'split', summary)
    db.commit()
    return summary
