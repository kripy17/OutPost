'''Live event stream - Server-Sent Events over the in-process broadcast.

- GET /events/stream - open a long-lived SSE connection; each fired alert is
  pushed as an `alert` event (webapp StatusBar / Monitor consume it). Falls
  back to polling in the client if this endpoint is unreachable.
'''

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from ..services import events_stream

router = APIRouter(tags=['events'])


@router.get('/events/stream', response_model=None)
def stream_events():
    return StreamingResponse(
        events_stream.stream_events(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # disable proxy buffering
        },
    )
