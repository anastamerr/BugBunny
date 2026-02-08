from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..config import get_settings

settings = get_settings()


def _postgres_connect_args() -> dict[str, object]:
    database_url = (settings.database_url or "").lower()
    if not database_url.startswith("postgresql"):
        return {}

    connect_timeout = max(1, int(settings.database_connect_timeout_seconds))
    statement_timeout = int(settings.database_statement_timeout_ms)
    connect_args: dict[str, object] = {"connect_timeout": connect_timeout}
    if statement_timeout > 0:
        connect_args["options"] = f"-c statement_timeout={statement_timeout}"
    return connect_args


engine_kwargs: dict[str, object] = {"pool_pre_ping": True}
connect_args = _postgres_connect_args()
if connect_args:
    engine_kwargs["connect_args"] = connect_args

engine = create_engine(settings.database_url, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
