'''Roadmap polish - the live SSE broadcast (push over polling).'''

import asyncio
from datetime import datetime, timezone

from ..core.schema import Alert
from ..services import events_stream


def _alert(rule_id: str = 'lolbin-abuse', severity: str = 'malicious') -> Alert:
    return Alert(
        run_id='r1',
        rule_id=rule_id,
        rule_name='LOLBin',
        severity=severity,  # type: ignore[arg-type]
        triggered_at=datetime.now(timezone.utc),
        details='osascript shell',
    )


def test_stream_yields_retry_then_published_alert():
    async def _run() -> list[str]:
        gen = events_stream.stream_events()
        try:
            first = await gen.__anext__()  # subscribe + retry frame
            events_stream.publish_alerts([_alert()])
            second = await gen.__anext__()
            return [first, second]
        finally:
            await gen.aclose()  # discard the subscriber so no cross-test leak

    frames = asyncio.run(_run())
    assert frames[0] == 'retry: 3000' + chr(10) * 2
    assert 'event: alert' in frames[1]
    assert '"rule_id": "lolbin-abuse"' in frames[1]
    assert '"severity": "malicious"' in frames[1]


def test_publish_fans_out_to_all_subscribers():
    async def _run() -> int:
        gen_a = events_stream.stream_events()
        gen_b = events_stream.stream_events()
        try:
            await gen_a.__anext__()
            await gen_b.__anext__()
            sent = events_stream.publish_alerts([_alert()])
            await gen_a.__anext__()
            await gen_b.__anext__()
            return sent
        finally:
            await gen_a.aclose()
            await gen_b.aclose()

    assert asyncio.run(_run()) == 2


def test_publish_is_noop_without_subscribers():
    '''Nobody listening -> fan-out is 0 and ingestion is unaffected.'''
    assert events_stream.publish_alerts([_alert()]) == 0
