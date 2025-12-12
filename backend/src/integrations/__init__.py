__all__ = ["PineconeService"]


def __getattr__(name: str):
    if name == "PineconeService":
        from .pinecone_client import PineconeService

        return PineconeService
    raise AttributeError(name)
