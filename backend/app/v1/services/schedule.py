"""Timezone-aware next-run calculation for scheduled scans."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def next_run(schedule, after: datetime) -> datetime:
    """Next occurrence strictly after ``after`` in the schedule's timezone.

    Wall-clock times are honoured across DST changes; a nonexistent local
    time (spring-forward gap) resolves forward by zoneinfo's fold rules.
    """
    zone = ZoneInfo(schedule.timezone)
    local_after = after.astimezone(zone)
    candidate = local_after.replace(hour=schedule.hour, minute=schedule.minute, second=0, microsecond=0)
    if schedule.frequency == "daily":
        if candidate <= local_after:
            candidate = (candidate + timedelta(days=1)).replace(hour=schedule.hour, minute=schedule.minute)
    else:
        weekday = schedule.weekday if schedule.weekday is not None else 0
        days_ahead = (weekday - candidate.weekday()) % 7
        candidate = candidate + timedelta(days=days_ahead)
        if candidate <= local_after:
            candidate = candidate + timedelta(days=7)
        candidate = candidate.replace(hour=schedule.hour, minute=schedule.minute)
    # Re-localise to apply the correct UTC offset for that date.
    naive = candidate.replace(tzinfo=None)
    return naive.replace(tzinfo=zone).astimezone(timezone.utc)
