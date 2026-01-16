from pathlib import Path

from src.services.scanner.repo_fetcher import RepoFetcher


def test_apply_github_token_only_for_https_github():
    fetcher = RepoFetcher()
    fetcher.settings.github_token = "token123"

    url = "https://github.com/acme/tools"
    assert (
        fetcher._apply_github_token(url, None)
        == "https://token123@github.com/acme/tools"
    )

    ssh_url = "git@github.com:acme/tools.git"
    assert fetcher._apply_github_token(ssh_url, None) == ssh_url


def test_analyze_repo_detects_languages_and_skips(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.ts").write_text("const x = 1", encoding="utf-8")

    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "skip.py").write_text("print('skip')", encoding="utf-8")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "lib.js").write_text("console.log('skip')", encoding="utf-8")

    fetcher = RepoFetcher()
    languages, file_count = fetcher.analyze_repo(tmp_path)

    assert languages == ["javascript", "python"]
    assert file_count == 3


def test_is_branch_missing_error_matches_known_messages():
    fetcher = RepoFetcher()
    assert fetcher._is_branch_missing_error("Remote branch main not found")
    assert fetcher._is_branch_missing_error("Couldn't find remote ref feature/x")
    assert not fetcher._is_branch_missing_error("fatal: authentication failed")
