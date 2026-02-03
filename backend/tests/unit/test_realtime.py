from src.realtime import sio


def test_socketio_config():
    assert getattr(sio, "async_mode", None) == "asgi"

    cors = getattr(sio, "cors_allowed_origins", None)
    if cors is None and getattr(sio, "eio", None) is not None:
        cors = getattr(sio.eio, "cors_allowed_origins", None)

    assert cors in ("*", ["*"])
