"""Production collection: daily catalog, rolling observations, independent stages."""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import re
import threading
import time

from .exporter import ExporterState
from .collection_log import CollectionLog
from .collection_journal import ObservationJournal
from .sensor_status import write_status
from .metrics import COMPONENT_SOURCE_KEYS, READING_METRICS, _escape
from .redfish import (RedfishAuthenticationError, RedfishCertificateError,
                      RedfishError, RedfishHTTPError, RedfishTimeoutError,
                      RedfishTransportError, RedfishUnavailableError)
from .sensor_collection import (CATALOG_TTL, SensorLedger, SensorResult,
                                checked_catalog, load_catalog, save_catalog)


def fetch_sensor(client, uri: str, timeout: float, *, priority: int = 1) -> SensorResult:
    """Classify transport failures without exposing their text or resource paths."""
    try:
        value, wall, mono = client.read_sensor(uri, timeout=timeout, priority=priority)
        return SensorResult(payload=value, observed_wall=wall, observed_monotonic=mono)
    except RedfishHTTPError as error:
        return SensorResult(status=error.status, retry_after=error.retry_after)
    except RedfishAuthenticationError:
        return SensorResult(error='authentication')
    except RedfishCertificateError:
        return SensorResult(error='certificate')
    except RedfishTimeoutError:
        return SensorResult(error='timeout')
    except RedfishUnavailableError:
        return SensorResult(status=503)
    except RedfishTransportError:
        return SensorResult(error='transport')
    except RedfishError:
        return SensorResult(error='metadata')


def coverage_metrics(status: dict, catalog_errors: int) -> bytes:
    fields = {
        'tracked': ('c880a_sensor_tracked', 'Catalog identities, including confirmed 404 exclusions'),
        'eligible': ('c880a_sensor_eligible', 'Catalog identities currently requiring observation'),
        'fresh': ('c880a_sensor_fresh', 'Eligible objects observed within the freshness limit'),
        'missing': ('c880a_sensor_missing', 'Eligible objects never successfully observed since startup'),
        'unresolved': ('c880a_sensor_unresolved', 'Eligible resources missing, stale or awaiting retry recovery'),
        'stale': ('c880a_sensor_stale', 'Eligible objects whose last observation is too old'),
        'numeric_unavailable': ('c880a_sensor_numeric_unavailable', 'Fresh objects without a finite numeric Reading'),
        'excluded_404': ('c880a_sensor_excluded_404', 'Resources excluded after three spaced consecutive 404 responses'),
        'max_source_age_seconds': ('c880a_sensor_max_observation_age_seconds', 'Oldest eligible response observation age; physical measurement age may be unknown'),
        'discovered_at': ('c880a_sensor_catalog_timestamp_seconds', 'Time of the last successful complete catalog reconciliation'),
        'errors': ('c880a_sensor_request_errors_total', 'Original failed sensor requests, including subsequently recovered requests'),
        'retries': ('c880a_sensor_retries_total', 'Sensor retry requests'),
        'recovered_retries': ('c880a_sensor_recovered_retries_total', 'Successful sensor responses following a failed request'),
        'exhausted_cycles': ('c880a_sensor_exhausted_recovery_total', 'Resource recovery attempts exhausted within their bounded retry cycle'),
    }
    lines = []
    for field, (metric, help_text) in fields.items():
        kind = 'counter' if metric.endswith('_total') else 'gauge'
        lines += [f'# HELP {metric} {help_text}.', f'# TYPE {metric} {kind}',
                  f'{metric} {status[field]}']
    lines += ['# HELP c880a_sensor_acquisition_paused Collection stopped after a security or metadata failure.',
              '# TYPE c880a_sensor_acquisition_paused gauge',
              f'c880a_sensor_acquisition_paused {int(bool(status["paused"]))}',
              '# HELP c880a_sensor_catalog_errors_total Failed full catalog attempts; prior catalog retained.',
              '# TYPE c880a_sensor_catalog_errors_total counter',
              f'c880a_sensor_catalog_errors_total {catalog_errors}']
    for field, metric in (('eligible', 'c880a_collection_sensor_eligible'),
                          ('fresh', 'c880a_collection_sensor_fresh'),
                          ('observed', 'c880a_collection_sensor_observed')):
        lines += [f'# HELP {metric} Current collector state for one tracked sensor; this is not a measurement.',
                  f'# TYPE {metric} gauge']
        for uri, resource in status['_resources'].items():
            labels = f'{{sensor_id="{_escape(resource["id"])}",sensor_uri="{_escape(uri)}"}}'
            lines.append(f'{metric}{labels} {int(resource[field])}')
    return ('\n'.join(lines) + '\n').encode()


def expire_cached_sensor_values(payload: bytes, now: float, max_age: float) -> bytes:
    """Retain completed-cache identities/timestamps, but omit expired measurements.

    A cache can be available for 600 seconds while a sensor's observation is
    already stale. Scraping that cache must not emit its old Reading as current.
    """
    lines = payload.splitlines()
    stamps = {}
    for line in lines:
        match = re.fullmatch(rb'c880a_sensor_observed_timestamp_seconds(\{.*\}) ([0-9.]+)', line)
        if match:
            stamps[match[1]] = float(match[2])
    numeric_names = {metric[0].encode() for metric in READING_METRICS.values()}
    numeric_names |= {b'c880a_sensor_reading', b'c880a_sensor_health'}
    output = []
    for line in lines:
        match = re.fullmatch(rb'(c880a_sensor_[a-z_]+)(\{.*\}) (.*)', line)
        if match and match[1] in numeric_names | {b'c880a_sensor_reading_available'}:
            age = now - stamps.get(match[2], 0)
            if not 0 <= age <= max_age:
                if match[1] == b'c880a_sensor_reading_available':
                    output.append(match[1] + match[2] + b' 0')
                continue
        output.append(line)
    return b'\n'.join(output) + b'\n'


class RollingExporterState(ExporterState):
    """One scheduler per claimed server. Scrapes only read completed cache state."""

    def __init__(self, client, workers: int, snapshot_file: Path | None = None,
                 *, log_dir: Path | None = None, target_id: str = 'standalone') -> None:
        super().__init__(client, workers, snapshot_file)
        self.ledger = SensorLedger(workers=min(3, workers))
        self.catalog_file = (snapshot_file.with_name(snapshot_file.name + '.catalog')
                             if snapshot_file is not None else None)
        self.catalog_binding = hashlib.sha256(client.base.encode()).hexdigest()
        self.discovery_ttl = CATALOG_TTL
        self.catalog_errors = 0
        self.catalog_file_lock = threading.Lock()
        self.saved_catalog_revision = -1
        self.catalog_due = 0.0
        self.auxiliary_worker: threading.Thread | None = None
        self.publication_interval = 2.0
        self.checkpoint_interval = 10.0
        self.last_checkpoint_monotonic = -math.inf
        self.last_checkpoint_signature = None
        self.cache_generation = -1
        self.cache_eligible = -1
        self.cache_oldest_observation_at = 0.0
        self.checkpoint_lock = threading.RLock()
        self.bootstrap_catalog = False
        self.optional_defer_until = 0.0
        self.log = None
        self.target_id = target_id
        self.journal = None
        if log_dir is not None:
            try:
                self.log = CollectionLog(log_dir)
                self.log.interrupt_pending(target_id, ('sensors', 'sensor_recovery', 'catalog', 'components', 'telemetry'))
                self.journal = ObservationJournal(self.log, target_id)
            except (OSError, ValueError):
                pass  # Logging must never prevent the independent exporter starting.
        if self.catalog_file and load_catalog(self.catalog_file, self.ledger, self.catalog_binding):
            self.bootstrap_catalog = True
            self.optional_defer_until = time.monotonic() + min(180.0, self.ledger.max_age)
            self.saved_catalog_revision = self.ledger.catalog_revision
            age = time.time() - self.ledger.discovered_at
            self.catalog_due = time.monotonic() + max(0, CATALOG_TTL - age)

    def stop_collector(self) -> None:
        super().stop_collector()
        worker = self.background_worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=3)
        self.ledger.stop()

    def _serve_export_cache(self) -> bytes:
        with self.checkpoint_lock:
            return self._serve_cohort()

    def _serve_cohort(self) -> bytes:
        body = super()._serve_export_cache()
        state = self.ledger.snapshot()
        body = expire_cached_sensor_values(body, time.time(), self.ledger.max_age)
        with self.lock:
            usable = self._snapshot_usable(time.time())
        cohort_matches = (self.cache_generation == self.ledger.generation and
                          self.cache_eligible == state['eligible'])
        if not cohort_matches:
            body = expire_cached_sensor_values(body, time.time(), -1)
        body = re.sub(rb'(?m)^c880a_target_up [01]$',
                      f'c880a_target_up {int(usable and state["complete"] and not state["unresolved"] and cohort_matches)}'.encode(), body)
        return body + coverage_metrics(state, self.catalog_errors)

    def _background_collect(self) -> None:
        self.ledger.start(lambda uri, timeout: fetch_sensor(self.client, uri, timeout,
                          priority=self.ledger.request_priority(uri)))
        next_auxiliary = 0.0
        try:
            while not self.collector_stopping:
                now = time.monotonic()
                state = self.ledger.snapshot()
                # Fatal authentication/certificate errors require operator recovery.
                safe_to_probe = state['paused'] not in ('authentication', 'certificate', 'internal')
                if state['paused'] == 'metadata':
                    self.catalog_due = min(self.catalog_due, now)
                optional_admissible = (state['complete'] or now >= self.optional_defer_until or
                                       now >= self.catalog_due)
                if (safe_to_probe and optional_admissible and now >= next_auxiliary and
                        (self.auxiliary_worker is None or not self.auxiliary_worker.is_alive())):
                    self.auxiliary_worker = threading.Thread(target=self._run_auxiliary,
                                                             name='redfish-optional', daemon=True)
                    self.auxiliary_worker.start()
                    next_auxiliary = now + (60 if not state['tracked'] else self.refresh_interval)
                try:
                    was_bootstrap = self.bootstrap_catalog
                    self._publish_rolling()
                    if was_bootstrap and not self.bootstrap_catalog:
                        next_auxiliary = min(next_auxiliary, now)
                except Exception:
                    # Storage/render failure cannot cancel the bounded sensor workers.
                    with self.lock:
                        self.export_cache_last_refresh_ok = False
                        self.export_cache_last_refresh_errors = 1
                with self.collection:
                    self.collection.wait(timeout=self.publication_interval)
        finally:
            self.ledger.stop()
            if self.journal:
                self.journal.interrupt(self.ledger.snapshot())
            with self.collection:
                self.background_worker = None

    def _run_auxiliary(self) -> None:
        """Catalog/System, components and telemetry use the same admission budget.

        Their completion is never a barrier for sensor observation publication.
        """
        try:
            discovered, _ = self._discover_for_collection()
            if time.monotonic() >= self.catalog_due:
                self._reconcile_catalog(discovered)
            if self.collector_stopping:
                return
            # Give the first independent observation round the ordinary slots.
            # A permanently unavailable member cannot starve optional work:
            # this startup-only deferral remains bounded at 180 seconds.
            if not self.ledger.snapshot()['complete'] and time.monotonic() < self.optional_defer_until:
                return
            started = time.monotonic()
            components, failures = self._logged_stage('components', lambda: self.client.component_snapshot(discovered))
            with self.lock:
                times = components.get('_source_observed_at', {})
                for source in COMPONENT_SOURCE_KEYS:
                    stamp = times.get(source) if isinstance(times, dict) else None
                    if source == 'system' and stamp is None:
                        stamp = discovered.get('system_observed_at')
                    if source in components and isinstance(stamp, (int, float)) and math.isfinite(stamp) and stamp > 0:
                        self.component_observations[source] = (components[source], stamp)
                self.component_errors = failures + int(bool(discovered.get('system_refresh_error')))
                self.stage_durations['components'] = time.monotonic() - started
            reports_uri = discovered.get('telemetry_reports_uri')
            if isinstance(reports_uri, str) and not self.collector_stopping:
                started = time.monotonic()
                reports, failures = self._logged_stage('telemetry', lambda: self.client.telemetry_snapshot(reports_uri))
                with self.lock:
                    for report in reports:
                        uri = report.get('uri')
                        if isinstance(uri, str):
                            self.telemetry_observations[uri] = self._merge_report(self.telemetry_observations.get(uri), report)
                    self.telemetry_reports_collected = len(reports)
                    self.telemetry_errors = failures
                    self.stage_durations['telemetry'] = time.monotonic() - started
        except (RedfishAuthenticationError, RedfishCertificateError) as error:
            with self.ledger.changed:
                self.ledger.paused = ('authentication' if isinstance(error, RedfishAuthenticationError) else 'certificate')
                self.ledger.changed.notify_all()
        except Exception:
            # Counts stay visible, without interpolating a BMC response into logs.
            with self.lock:
                self.component_errors += 1

    def _logged_stage(self, operation, fetch):
        started = time.monotonic()
        cycle = self.log.begin(self.target_id, operation) if self.log else None
        result = None
        try:
            result = fetch()
            return result
        finally:
            if self.log:
                errors = result[1] if result is not None else 1
                self.log.record(self.target_id, operation,
                    'failed' if result is None else 'partial' if errors else 'complete', cycle,
                    errors=errors, duration_seconds=round(time.monotonic() - started, 3))

    def _reconcile_catalog(self, discovered: dict) -> bool:
        started = time.monotonic()
        with self.lock:
            self.last_attempt_at = time.time()
        cycle = self.log.begin(self.target_id, 'catalog') if self.log else None
        success = False
        seeds = {}
        def on_page(items, count):
            wall, mono = time.time(), time.monotonic()
            for item in items:
                uri = item.get('@odata.id')
                if isinstance(uri, str) and isinstance(item.get('Id'), str):
                    seeds[uri] = SensorResult(payload=item, observed_wall=wall, observed_monotonic=mono)
        try:
            rows, errors, count = self.client.sensor_snapshot(discovered['sensor_uri'],
                                                             workers=3, on_page=on_page)
            if self.collector_stopping:
                return False
            if errors or type(count) is not int or count != len(rows) or count != len(seeds):
                raise ValueError('Incomplete catalog')
            identities = checked_catalog(rows)
            metadata = list(identities.values())
            changed = metadata != self.ledger.catalog()
            with self.ledger.lock:
                existing = {uri for uri, resource in self.ledger.rows.items()
                            if resource.value is not None and not resource.excluded and
                            resource.metadata == identities.get(uri)}
                cold = not self.ledger.rows
            # Catalog page bursts must not declare cold acquisition complete.
            # Unchanged already-observed identities may retain actual newer
            # page responses, without postponing their rolling renewal.
            self.ledger.reconcile(rows, observed={uri: value for uri, value in seeds.items()
                                                 if uri in existing})
            if cold:
                self.bootstrap_catalog = True
                self.optional_defer_until = time.monotonic() + min(180.0, self.ledger.max_age)
            success = True
            if changed:
                with self.checkpoint_lock:
                    with self.lock:
                        self.export_cache_payload = None
                        self.export_cache_completed_at = 0.0
                if self.export_cache_file:
                    self.export_cache_file.unlink(missing_ok=True)
            self.catalog_due = time.monotonic() + CATALOG_TTL
            if self.catalog_file:
                try:
                    with self.catalog_file_lock:
                        self.saved_catalog_revision = save_catalog(self.catalog_file, self.ledger, self.catalog_binding)
                except (OSError, ValueError):
                    # The in-memory validated catalog remains useful on a full disk.
                    pass
            return True
        except (RedfishAuthenticationError, RedfishCertificateError):
            raise
        except (RedfishError, ValueError, KeyError):
            self.catalog_errors += 1
            self.catalog_due = time.monotonic() + 60
            return False
        finally:
            with self.lock:
                self.stage_durations['discovery'] = time.monotonic() - started
            if self.log:
                self.log.record(self.target_id, 'catalog', 'complete' if success else 'failed', cycle,
                                errors=int(not success), duration_seconds=round(time.monotonic() - started, 3),
                                tracked=self.ledger.snapshot()['tracked'])

    def _publish_rolling(self) -> None:
        with self.ledger.lock:
            readings, timestamps = self.ledger.publication()
            state = self.ledger.snapshot()
            generation = self.ledger.generation
        state['warming'] = self.bootstrap_catalog
        if state['complete'] and not state['unresolved']:
            self.bootstrap_catalog = False
        if self.journal:
            self.journal.observe(state)
        if self.catalog_file and state['tracked'] and state['catalog_revision'] != self.saved_catalog_revision:
            try:
                with self.catalog_file_lock:
                    self.saved_catalog_revision = save_catalog(self.catalog_file, self.ledger, self.catalog_binding)
            except (OSError, ValueError):
                pass
        now = time.time()
        fresh = [(row, timestamps[row['@odata.id']]) for row in readings
                 if 0 <= now - timestamps[row['@odata.id']] <= self.ledger.max_age]
        with self.lock:
            self.sensor_observations = {row['@odata.id']: (row, stamp) for row, stamp in fresh}
            self.sensor_expected = state['eligible']
            self.ready = bool(state['complete']) and not state['unresolved']
            self.sensor_errors = state['unresolved'] + int(bool(state['paused']))
            self.last_attempt_at = max(self.last_attempt_at, state['last_attempt_wall'])
            self.collecting = bool(state['inflight'] or (self.auxiliary_worker and self.auxiliary_worker.is_alive()))
            if state['complete'] and not state['unresolved']:
                self.last_success_at = max(timestamps.values(), default=0.0)
            self.export_cache_last_sensor_ok = bool(state['complete']) and not state['unresolved']
            component_errors, telemetry_errors = self.component_errors, self.telemetry_errors
            durations = self.stage_durations.copy()
            self.export_cache_last_refresh_errors = self.sensor_errors + component_errors + telemetry_errors
            self.export_cache_last_refresh_ok = bool(state['complete']) and not self.export_cache_last_refresh_errors
            # A request's admission time cannot stand in for its completion.
            self.export_cache_last_refresh_completed_at = max(
                self.export_cache_completed_at, state['last_completion_wall'])
        payload = (self._render_observations(sensor_max_age=self.ledger.max_age) + coverage_metrics(state, self.catalog_errors) +
                   ('# HELP c880a_snapshot_timestamp_seconds Time of incremental collector status assembly; measurement sources have separate timestamps.\n'
                    '# TYPE c880a_snapshot_timestamp_seconds gauge\n'
                    f'c880a_snapshot_timestamp_seconds {now:.3f}\n').encode())
        with self.lock:
            self.payload = payload
        self.publish_snapshot(payload)
        if self.snapshot_file:
            try:
                write_status(self.snapshot_file.with_name(self.snapshot_file.name + '.status'), state)
            except (OSError, ValueError):
                pass
        signature = (generation, state['successes'], state['eligible'])
        # A previously completed cohort can expire just before the usual
        # checkpoint interval, even though readers already renewed it. Publish
        # the genuinely newer complete cohort early enough for background wake,
        # render and scheduling delay; scraping still only reads that cache.
        expiry_margin = min(self.ledger.max_age / 4,
                            self.checkpoint_interval + 2 * self.publication_interval + 6)
        approaching_expiry = (self.cache_oldest_observation_at > 0 and
                              now - self.cache_oldest_observation_at >=
                              self.ledger.max_age - expiry_margin)
        if (state['complete'] and not state['unresolved'] and len(fresh) == state['eligible'] and signature != self.last_checkpoint_signature and
                (approaching_expiry or
                 time.monotonic() - self.last_checkpoint_monotonic >= self.checkpoint_interval)):
            # The completed sensor cohort is assembled independently of optional stages.
            with self.checkpoint_lock:
                self._cache_completed_pass([row for row, _ in fresh], self.sensor_observations.copy(),
                                           state['eligible'], component_errors, telemetry_errors, durations)
                self.last_checkpoint_monotonic = time.monotonic()
                self.last_checkpoint_signature = signature
                self.cache_generation, self.cache_eligible = generation, state['eligible']
                self.cache_oldest_observation_at = min((stamp for _, stamp in fresh), default=0.0)
