from __future__ import annotations
from collections import deque
from datetime import datetime, timedelta, timezone
import math, random
from ..schemas.dashboard import DashboardState, HistoryPoint, Metrics, SecurityEvent, SecurityState, Finding, VPNState

class MockDataProvider:
    def __init__(self) -> None:
        self.started_at = datetime.now(timezone.utc)
        self.phase = random.random() * math.tau
        self.step = 0
        self.history: deque[HistoryPoint] = deque(maxlen=60)
        self.events: deque[SecurityEvent] = deque(maxlen=12)
        self._seed_history()

    def _seed_history(self):
        now = datetime.now(timezone.utc)
        for i in range(60, 0, -1):
            ts = now - timedelta(seconds=i * 2)
            pps, bps, risk = self._values(i * -2)
            self.history.append(self._point(ts, pps, bps, risk))
        self.events.appendleft(SecurityEvent(timestamp=now-timedelta(seconds=32), type='INFO', title='Traffic pattern normalized', severity='INFO', description='Encrypted tunnel traffic returned to its expected baseline.'))
        self.events.appendleft(SecurityEvent(timestamp=now-timedelta(seconds=71), type='FLOW', title='New VPN flow detected', severity='INFO', description='A new encrypted flow was observed between the active endpoints.'))

    def _values(self, offset: int = 0):
        t = self.step + offset / 2
        base = 420 + 95 * math.sin(t / 5.0 + self.phase) + 35 * math.sin(t / 1.7)
        burst = 0
        if self.step % 95 in range(0, 8):
            burst = 650 * math.sin((self.step % 95) / 8 * math.pi)
        pps = max(120, base + burst + random.gauss(0, 18))
        bps = max(150_000, pps * (760 + 55 * math.sin(t / 8)) + random.gauss(0, 18_000))
        risk = int(max(7, min(94, 10 + (pps - 350) / 22 + (bps - 450_000) / 180_000 + random.gauss(0, 2))))
        return pps, bps, risk

    @staticmethod
    def _risk_level(score: int):
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH'
        if score >= 30: return 'MEDIUM'
        return 'LOW'

    def _point(self, ts, pps, bps, risk):
        inbound = bps * (0.48 + random.random() * 0.08)
        return HistoryPoint(timestamp=ts, packets_per_second=round(pps, 1), bytes_per_second=round(bps), risk_score=risk, inbound_bps=round(inbound), outbound_bps=round(bps-inbound))

    def snapshot(self) -> DashboardState:
        self.step += 1
        now = datetime.now(timezone.utc)
        pps, bps, risk = self._values()
        anomaly = risk >= 30 or self.step % 47 == 0
        level = self._risk_level(risk)
        if anomaly and (not self.events or (now - self.events[0].timestamp).total_seconds() > 7):
            severity = 'CRITICAL' if level == 'CRITICAL' else 'HIGH' if level == 'HIGH' else 'MEDIUM'
            title = 'Abnormal packet rate detected' if pps > 700 else 'Elevated encrypted traffic'
            self.events.appendleft(SecurityEvent(timestamp=now, type='ANOMALY', title=title, severity=severity, description='Observed traffic exceeded the current behavioral baseline.'))
        elif self.step % 23 == 0:
            self.events.appendleft(SecurityEvent(timestamp=now, type='INFO', title='Traffic pattern normalized', severity='INFO', description='Observed flow characteristics returned toward baseline.'))

        self.history.append(self._point(now, pps, bps, risk))
        findings = []
        if anomaly:
            findings.append(Finding(id='TRAFFIC-001', title='Traffic anomaly', severity=level if level in {'HIGH','CRITICAL'} else 'MEDIUM', description='The current traffic profile differs from the learned baseline.', reason='Packet and byte rates are elevated relative to recent behavior.'))
        metrics = Metrics(
            packets_per_second=round(pps), bytes_per_second=round(bps),
            total_packets=max(0, int(self.step * pps * 2)), total_bytes=max(0, int(self.step * bps * 2)),
            active_flows=max(2, int(8 + pps / 180 + random.gauss(0, 1))),
            average_packet_size=round(bps / max(pps, 1)),
            inbound_bps=round(bps * 0.52), outbound_bps=round(bps * 0.48),
        )
        vpn = VPNState(status='CONNECTED', endpoint_a='Computer A · Saran', endpoint_a_ip='192.168.1.101', endpoint_b='Computer B · Shrey', endpoint_b_ip='10.0.0.47', tunnel='IPsec / ESP', uptime_seconds=int((now-self.started_at).total_seconds()), protocol='IKEv2 / ESP', encryption='AES-256-GCM')
        return DashboardState(timestamp=now, vpn=vpn, metrics=metrics, security=SecurityState(risk_score=risk, risk_level=level, anomaly_detected=anomaly, findings=findings), events=list(self.events), history=list(self.history), mode='MOCK')

provider = MockDataProvider()
