from pathlib import Path


def test_alembic_versions_exist():
    root = Path(__file__).resolve().parents[2]
    versions_dir = root / "alembic" / "versions"
    assert versions_dir.is_dir()
    assert any(versions_dir.glob("*.py"))
