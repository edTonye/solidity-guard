from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_dir() -> Path:
    return FIXTURES / "vulnerable"


@pytest.fixture
def safe_dir() -> Path:
    return FIXTURES / "safe"
