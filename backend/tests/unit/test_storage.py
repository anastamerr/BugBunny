from types import SimpleNamespace

from src.services import storage


class FakeBucket:
    def __init__(self):
        self.upload_calls = []
        self.remove_calls = []
        self.files = []
        self.public_url = "https://files.example.com/report.pdf"
        self.download_data = b"pdf-bytes"
        self.raise_on_upload = False
        self.raise_on_remove = False

    def upload(self, path, data, file_options=None):  # noqa: ANN001
        if self.raise_on_upload:
            raise RuntimeError("upload failed")
        self.upload_calls.append((path, data, file_options))
        self.files.append({"name": path})

    def get_public_url(self, path):  # noqa: ANN001
        return self.public_url

    def list(self):
        return list(self.files)

    def download(self, path):  # noqa: ANN001
        return self.download_data

    def remove(self, paths):  # noqa: ANN001
        if self.raise_on_remove:
            raise RuntimeError("remove failed")
        self.remove_calls.append(paths)


class FakeStorage:
    def __init__(self, bucket):
        self.bucket = bucket

    def from_(self, name):  # noqa: ANN001
        assert name == storage.BUCKET_NAME
        return self.bucket


class FakeClient:
    def __init__(self, bucket):
        self.storage = FakeStorage(bucket)


def _settings_with_supabase():
    return SimpleNamespace(
        supabase_url="https://supabase.example.com",
        supabase_service_key="service-key",
    )


def test_get_supabase_client_returns_none_without_config(monkeypatch):
    monkeypatch.setattr(
        storage, "get_settings", lambda: SimpleNamespace(supabase_url=None, supabase_service_key=None)
    )
    assert storage._get_supabase_client() is None


def test_upload_pdf_success(monkeypatch):
    bucket = FakeBucket()
    client = FakeClient(bucket)
    monkeypatch.setattr(storage, "get_settings", _settings_with_supabase)
    monkeypatch.setattr(storage, "create_client", lambda url, key: client)

    url = storage.upload_pdf("scan-123", b"data", upsert=True)

    assert url == bucket.public_url
    path, data, options = bucket.upload_calls[0]
    assert path == "scan-123.pdf"
    assert data == b"data"
    assert options["content-type"] == "application/pdf"
    assert options["upsert"] == "true"


def test_upload_pdf_returns_existing_on_failure(monkeypatch):
    bucket = FakeBucket()
    bucket.raise_on_upload = True
    client = FakeClient(bucket)
    monkeypatch.setattr(storage, "get_settings", _settings_with_supabase)
    monkeypatch.setattr(storage, "create_client", lambda url, key: client)

    monkeypatch.setattr(storage, "get_pdf_url", lambda scan_id: "https://existing")

    url = storage.upload_pdf("scan-456", b"data", upsert=False)
    assert url == "https://existing"


def test_get_pdf_url_found(monkeypatch):
    bucket = FakeBucket()
    bucket.files = [{"name": "scan-999.pdf"}]
    client = FakeClient(bucket)
    monkeypatch.setattr(storage, "get_settings", _settings_with_supabase)
    monkeypatch.setattr(storage, "create_client", lambda url, key: client)

    assert storage.get_pdf_url("scan-999") == bucket.public_url


def test_download_pdf_reads_stream(monkeypatch):
    bucket = FakeBucket()
    bucket.download_data = SimpleNamespace(read=lambda: b"stream-bytes")
    client = FakeClient(bucket)
    monkeypatch.setattr(storage, "get_settings", _settings_with_supabase)
    monkeypatch.setattr(storage, "create_client", lambda url, key: client)

    assert storage.download_pdf("scan-111") == b"stream-bytes"


def test_delete_pdf_returns_false_on_error(monkeypatch):
    bucket = FakeBucket()
    bucket.raise_on_remove = True
    client = FakeClient(bucket)
    monkeypatch.setattr(storage, "get_settings", _settings_with_supabase)
    monkeypatch.setattr(storage, "create_client", lambda url, key: client)

    assert storage.delete_pdf("scan-222") is False
