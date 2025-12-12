import pytest
from unittest.mock import MagicMock, patch


@patch("src.integrations.pinecone_client.SentenceTransformer")
@patch("src.integrations.pinecone_client.Pinecone")
def test_embed_text_returns_list(mock_pc_cls, mock_encoder_cls, monkeypatch):
    monkeypatch.setenv("PINECONE_API_KEY", "test-key")

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

