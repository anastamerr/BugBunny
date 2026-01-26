import pytest
from unittest.mock import MagicMock, patch


@patch("src.integrations.pinecone_client.ServerlessSpec")
@patch("src.integrations.pinecone_client.SentenceTransformer")
@patch("src.integrations.pinecone_client.Pinecone")
def test_embed_text_returns_list(mock_pc_cls, mock_encoder_cls, mock_spec_cls, monkeypatch):
    monkeypatch.setenv("PINECONE_API_KEY", "test-key")
    from src.config import get_settings

    get_settings.cache_clear()

    mock_pc = MagicMock()
    mock_pc.list_indexes.return_value = []
    mock_pc_cls.return_value = mock_pc
    mock_pc.Index.return_value = MagicMock()

    mock_encoder = MagicMock()
    mock_encoder.encode.return_value = [0.1, 0.2]
    mock_encoder_cls.return_value = mock_encoder

    from src.integrations.pinecone_client import PineconeService

    service = PineconeService()
    vec = service.embed_text("hello")
    assert vec == [0.1, 0.2]


@patch("src.integrations.pinecone_client.ServerlessSpec")
@patch("src.integrations.pinecone_client.SentenceTransformer")
@patch("src.integrations.pinecone_client.Pinecone")
def test_find_similar_bugs_applies_metadata_filter(
    mock_pc_cls, mock_encoder_cls, mock_spec_cls, monkeypatch
):
    monkeypatch.setenv("PINECONE_API_KEY", "test-key")
    from src.config import get_settings

    get_settings.cache_clear()

    mock_pc = MagicMock()
    mock_pc.list_indexes.return_value = []
    mock_pc_cls.return_value = mock_pc

    bugs_index = MagicMock()
    patterns_index = MagicMock()
    memory_index = MagicMock()
    mock_pc.Index.side_effect = [bugs_index, patterns_index, memory_index]

    mock_encoder = MagicMock()
    mock_encoder.encode.return_value = [0.1, 0.2]
    mock_encoder_cls.return_value = mock_encoder

    from src.integrations.pinecone_client import PineconeService

    service = PineconeService()
    service.find_similar_bugs(
        "title",
        "desc",
        top_k=3,
        metadata_filter={"repo_full_name": {"$eq": "acme/repo"}},
    )

    _, kwargs = bugs_index.query.call_args
    assert kwargs["filter"] == {"repo_full_name": {"$eq": "acme/repo"}}
