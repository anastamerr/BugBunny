from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_generate_success():
    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "hello"}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__.return_value = mock_client

    with patch(
        "src.services.intelligence.llm_service.httpx.AsyncClient",
        return_value=mock_async_client,
    ):
        from src.services.intelligence.llm_service import OllamaService

        service = OllamaService(host="http://test")
        out = await service.generate("prompt")
        assert out == "hello"


@pytest.mark.asyncio
async def test_is_available_true_on_200():
    mock_response = MagicMock(status_code=200)
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__.return_value = mock_client

    with patch(
        "src.services.intelligence.llm_service.httpx.AsyncClient",
        return_value=mock_async_client,
    ):
        from src.services.intelligence.llm_service import OllamaService

        service = OllamaService(host="http://test")
        assert await service.is_available() is True


@pytest.mark.asyncio
async def test_generate_timeout_raises():
    mock_client = AsyncMock()
    mock_client.post.side_effect = Exception("timeout")

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__.return_value = mock_client

    with patch(
        "src.services.intelligence.llm_service.httpx.AsyncClient",
        return_value=mock_async_client,
    ):
        from src.services.intelligence.llm_service import OllamaService

        service = OllamaService(host="http://test")
        with pytest.raises(Exception):
            await service.generate("prompt")

