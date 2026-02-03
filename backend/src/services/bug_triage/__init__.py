from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .auto_router import AutoRouter
    from .bug_correlation import BugCorrelationService
    from .classifier import BugClassifier
    from .duplicate_detector import DuplicateDetector

__all__ = ["AutoRouter", "BugClassifier", "BugCorrelationService", "DuplicateDetector"]


def __getattr__(name: str):  # noqa: ANN001
    if name == "AutoRouter":
        from .auto_router import AutoRouter

        return AutoRouter
    if name == "BugClassifier":
        from .classifier import BugClassifier

        return BugClassifier
    if name == "BugCorrelationService":
        from .bug_correlation import BugCorrelationService

        return BugCorrelationService
    if name == "DuplicateDetector":
        from .duplicate_detector import DuplicateDetector

        return DuplicateDetector
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
