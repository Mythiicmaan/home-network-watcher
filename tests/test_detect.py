"""Detection rules, proven with simulated data. Nothing is spoofed on a real network."""

from datetime import datetime, time, timedelta

from netwatch import detect

GW = "192.0.2.1"
GW_MAC = "02:00:00:00:00:01"
EVIL = "02:00:00:00:0e:01"


# ---------------------------------------------------------------- scan health


def test_typical_count_needs_history():
    assert detect.typical_device_count([10, 11]) is None
    assert detect.typical_device_count([10, 12, 11, 30]) == 11


def test_healthy_scan():
    h = detect.assess_scan(
        error=None, found=10, typical=11, gateway_ip=GW, gateway_seen=True, vpn_up=[]
    )
    assert h.ok and not h.degraded


def test_few_devices_means_degraded_with_vpn_hint():
    h = detect.assess_scan(
        error=None, found=2, typical=12, gateway_ip=GW, gateway_seen=True, vpn_up=["NordLynx"]
    )
    assert h.ok and h.degraded
    assert "found 2 devices, usually 12" in h.reason
    assert "NordLynx" in h.reason


def test_missing_gateway_means_degraded():
    h = detect.assess_scan(
        error=None, found=12, typical=12, gateway_ip=GW, gateway_seen=False, vpn_up=[]
    )
    assert h.degraded and "gateway" in h.reason and "Is a VPN connected?" in h.reason


def test_error_is_a_failed_scan_not_degraded():
    h = detect.assess_scan(
        error="boom", found=0, typical=None, gateway_ip=None, gateway_seen=False, vpn_up=[]
    )
    assert not h.ok and not h.degraded and h.reason == "boom"


def test_first_scans_without_history_are_judged_on_gateway_only():
    h = detect.assess_scan(
        error=None, found=3, typical=None, gateway_ip=GW, gateway_seen=True, vpn_up=[]
    )
    assert not h.degraded


# ---------------------------------------------------------------- gateway MAC (T1557.002)


def test_gateway_first_sighting_is_trusted_silently():
    f = detect.check_gateway(GW, None, {GW: GW_MAC})
    assert f.first_sighting and not f.changed


def test_gateway_unchanged():
    f = detect.check_gateway(GW, GW_MAC, {GW: GW_MAC, "192.0.2.5": "02:00:00:00:00:05"})
    assert not f.changed


def test_gateway_mac_change_is_detected_with_evidence():
    # Simulated ARP poisoning: an attacker at .66 answers for the gateway's IP too.
    table = {GW: EVIL, "192.0.2.66": EVIL, "192.0.2.5": "02:00:00:00:00:05"}
    f = detect.check_gateway(GW, GW_MAC, table)
    assert f.changed
    assert f.observed_mac == EVIL
    assert f.also_claimed_by == ("192.0.2.66",)
    assert f.dedup_key == f"gateway_mac_change:{GW_MAC}>{EVIL}"


def test_gateway_not_seen_returns_none():
    assert detect.check_gateway(GW, GW_MAC, {"192.0.2.5": "02:00:00:00:00:05"}) is None
    assert detect.check_gateway(None, GW_MAC, {GW: GW_MAC}) is None


# ---------------------------------------------------------------- IP conflicts


A, B, C = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"
IP = "192.0.2.50"


def test_flip_flop_is_a_conflict():
    history = [{IP: A}, {IP: B}, {IP: A}]
    [c] = detect.find_ip_conflicts(history)
    assert c.ip == IP and c.macs == (A, B)
    assert c.dedup_key == f"ip_conflict:{IP}:{A}|{B}"


def test_one_way_change_is_dhcp_reuse_not_a_conflict():
    assert detect.find_ip_conflicts([{IP: A}, {IP: A}, {IP: B}, {IP: B}]) == []


def test_stable_ip_and_short_history():
    assert detect.find_ip_conflicts([{IP: A}, {IP: A}, {IP: A}]) == []
    assert detect.find_ip_conflicts([{IP: A}, {IP: B}]) == []


def test_conflict_window_and_gaps():
    # A and B alternate, with a scan where the IP is absent: still a conflict.
    assert detect.find_ip_conflicts([{IP: A}, {}, {IP: B}, {IP: A}])
    # The flip-flop is older than the window: not reported now.
    old = [{IP: A}, {IP: B}, {IP: A}, {IP: A}, {IP: A}, {IP: A}, {IP: A}]
    assert detect.find_ip_conflicts(old, window=4) == []


def test_conflict_skips_gateway_ip():
    assert detect.find_ip_conflicts([{IP: A}, {IP: B}, {IP: A}], skip_ips={IP}) == []


def test_three_way_conflict():
    [c] = detect.find_ip_conflicts([{IP: A}, {IP: B}, {IP: C}, {IP: A}])
    assert c.macs == (A, B, C)


# ---------------------------------------------------------------- devices and online status


def test_new_macs_keeps_order_and_dedupes():
    assert detect.new_macs([A, B, A, C], {B}) == [A, C]


def test_online_means_seen_in_last_two_good_scans():
    t = datetime(2027, 1, 4, 12, 0)
    starts = [t - timedelta(minutes=10), t - timedelta(minutes=5), t]
    cutoff = detect.online_cutoff(starts)
    assert cutoff == t - timedelta(minutes=5)
    assert detect.is_online(t - timedelta(minutes=5), cutoff)
    assert not detect.is_online(t - timedelta(minutes=10), cutoff)
    assert detect.online_cutoff([]) is None
    assert detect.online_cutoff([t]) == t


def test_returning_unknown():
    assert detect.is_returning_unknown("unknown", 3)
    assert not detect.is_returning_unknown("unknown", 2)
    assert not detect.is_returning_unknown("known", 9)


# ---------------------------------------------------------------- schedule helpers


def test_quiet_hours_including_overnight():
    night = (time(22, 0), time(7, 0))
    assert detect.in_quiet_hours(time(23, 30), night)
    assert detect.in_quiet_hours(time(6, 59), night)
    assert not detect.in_quiet_hours(time(7, 0), night)
    assert not detect.in_quiet_hours(time(12, 0), night)
    assert detect.in_quiet_hours(time(13, 0), (time(12, 0), time(14, 0)))
    assert not detect.in_quiet_hours(time(13, 0), None)


def test_digest_due_once_per_week_on_sunday_evening():
    sunday_7pm = datetime(2027, 1, 10, 19, 0)
    assert sunday_7pm.weekday() == 6
    assert detect.digest_due(sunday_7pm, 6, 18, None)
    assert not detect.digest_due(sunday_7pm, 6, 18, detect.week_key(sunday_7pm))
    assert not detect.digest_due(sunday_7pm.replace(hour=17), 6, 18, None)
    assert not detect.digest_due(datetime(2027, 1, 11, 19, 0), 6, 18, None)
