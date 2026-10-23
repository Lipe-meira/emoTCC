"""Metrics use only final per-event decisions, never the number of rule alerts."""


def confusion_metrics(tp, fp, tn, fn):
    def divide(a, b):
        return a / b if b else None
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': divide(tp, tp+fp), 'recall': divide(tp, tp+fn),
            'f1': divide(2*tp, 2*tp+fp+fn), 'fpr': divide(fp, fp+tn),
            'events': tp+fp+tn+fn, 'suspicious_events': tp+fp, 'events_without_alert': tn+fn}


def evaluate_decisions(db):
    metrics = {}
    for detector in ('A', 'B'):
        tp, fp, tn, fn = db.execute('''SELECT
            coalesce(sum(e.label!='BENIGN' AND d.suspicious=1),0),
            coalesce(sum(e.label='BENIGN' AND d.suspicious=1),0),
            coalesce(sum(e.label='BENIGN' AND d.suspicious=0),0),
            coalesce(sum(e.label!='BENIGN' AND d.suspicious=0),0)
            FROM decisions d JOIN events e USING(event_id) WHERE d.detector=?''', (detector,)).fetchone()
        metrics[detector] = confusion_metrics(tp, fp, tn, fn)
        metrics[detector].update(dict(zip(['alerts','rules_evaluated','detection_seconds'], db.execute(
            'SELECT coalesce(sum(alert_count),0),coalesce(sum(rules_evaluated),0),coalesce(sum(detection_seconds),0) FROM decisions WHERE detector=?', (detector,)).fetchone())))
        metrics[detector]['mean_detection_seconds'] = metrics[detector]['detection_seconds'] / metrics[detector]['events'] if metrics[detector]['events'] else None
    return metrics
