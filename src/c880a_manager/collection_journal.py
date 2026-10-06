"""Bounded observation windows and correlated recovery summaries."""
from __future__ import annotations

import time

from .collection_log import CollectionLog


def counts(state: dict) -> dict:
    return {key: int(state[key]) for key in ('tracked', 'eligible', 'fresh', 'missing', 'stale',
                                            'numeric_unavailable', 'excluded_404', 'unresolved')}


class ObservationJournal:
    """Timings cover scheduler windows/recovery observation, not per-GET batches."""
    def __init__(self, log: CollectionLog, target_id: str, *, interval: float = 120,
                 monotonic=time.monotonic):
        self.log, self.target_id, self.interval, self.monotonic = log, target_id, interval, monotonic
        self.cycle = None
        self.started = self.monotonic()
        self.baseline = None
        self.last_errors = 0
        self.recovery = None
        self.exhausted_at_attempt = -1
        self.window_codes = set()

    def observe(self, state: dict) -> None:
        now = self.monotonic()
        if self.baseline is None:
            self.baseline = state.copy()
            self.started = now
            self.cycle = self.log.begin(self.target_id, 'sensors', **counts(state))
        new_errors = state['errors'] > self.last_errors
        new_failure_events = [event for event in state.get('failure_events', []) if event[0] > self.last_errors]
        self.window_codes.update(code for _, _, code, _ in new_failure_events)
        resources = state['_resources']
        warming = state.get('warming', False)
        needs_recovery = new_errors or (state['unresolved'] and not warming) or state['stale']
        if (self.recovery is None and state['tracked'] and needs_recovery and
                state['attempts'] != self.exhausted_at_attempt):
            cohort = {uri for uri, row in resources.items() if row['unresolved'] and
                      (not warming or row['observed'])}
            cohort.update(uri for _, uri, _, _ in new_failure_events)
            initial = len(cohort)
            identifier = self.log.begin(self.target_id, 'sensor_recovery', cycle_id=self.cycle,
                                        initial_missing=initial, **counts(state),
                                        error_codes=state['error_codes'])
            self.recovery = {'id': identifier, 'started': min((event[3] for event in new_failure_events), default=now),
                             'original_started': self.started,
                             'initial': initial, 'excluded': state['excluded_404'],
                             'retries': state['retries'], 'errors': self.last_errors,
                             'reported': now, 'exhausted': state['exhausted_cycles'],
                             'codes': set(state['error_codes']) | {code for _, _, code, _ in new_failure_events},
                             'cohort': cohort, 'additional': set()}
        recovery = self.recovery
        if recovery is not None:
            recovery['codes'].update(state['error_codes'])
            recovery['codes'].update(code for _, _, code, _ in new_failure_events)
            recovery['additional'].update(uri for _, uri, _, _ in new_failure_events if uri not in recovery['cohort'])
            resolved = bool(state['complete']) and state['unresolved'] == 0
            exhausted = bool(state['paused']) or state['exhausted_cycles'] > recovery['exhausted']
            terminal = resolved or exhausted
            if terminal or now - recovery['reported'] >= self.interval:
                new_exclusions = max(0, state['excluded_404'] - recovery['excluded'])
                original = [resources.get(uri) for uri in recovery['cohort']]
                recovered = sum(row is not None and row['fresh'] and not row['unresolved'] for row in original)
                self.log.record(self.target_id, 'sensor_recovery',
                    'recovered' if resolved else 'exhausted' if exhausted else 'partial', recovery['id'],
                    terminal=terminal, initial_missing=recovery['initial'],
                    recovered=recovered, additional_missing=len(recovery['additional']),
                    original_exclusions=sum(row is not None and not row['eligible'] for row in original),
                    original_unresolved=sum(row is not None and row['unresolved'] for row in original),
                    catalog_removed=sum(row is None for row in original),
                    new_exclusions=new_exclusions, **counts(state),
                    retries=max(0, state['retries'] - recovery['retries']),
                    errors=max(0, state['errors'] - recovery['errors']),
                    recovery_seconds=round(now - recovery['started'], 3),
                    total_seconds=round(now - recovery['original_started'], 3),
                    error_codes=sorted(recovery['codes']))
                recovery['reported'] = now
                if terminal:
                    self.recovery = None
                    if exhausted and not resolved:
                        self.exhausted_at_attempt = state['attempts']
        self.last_errors = state['errors']
        if now - self.started >= self.interval:
            self.log.record(self.target_id, 'sensors',
                'complete' if state['complete'] and not state['unresolved'] else 'partial', self.cycle,
                **counts(state), duration_seconds=round(now - self.started, 3),
                retries=max(0, state['retries'] - self.baseline['retries']),
                errors=max(0, state['errors'] - self.baseline['errors']),
                request_count=max(0, state['attempts'] - self.baseline['attempts']),
                error_codes=sorted(self.window_codes | set(state['error_codes'])))
            self.cycle = self.log.begin(self.target_id, 'sensors', **counts(state))
            self.started, self.baseline = now, state.copy()
            self.window_codes.clear()

    def interrupt(self, state: dict):
        now = self.monotonic()
        if self.baseline is not None:
            self.log.record(self.target_id, 'sensors', 'interrupted', self.cycle,
                            **counts(state), duration_seconds=round(now - self.started, 3))
        if self.recovery is not None:
            r = self.recovery
            self.log.record(self.target_id, 'sensor_recovery', 'interrupted', r['id'],
                            **counts(state), initial_missing=r['initial'],
                            recovery_seconds=round(now - r['started'], 3),
                            total_seconds=round(now - r['original_started'], 3))
