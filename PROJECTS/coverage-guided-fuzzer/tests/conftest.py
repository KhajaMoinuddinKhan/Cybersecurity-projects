"""Fixtures.

The build is done once per session rather than per test: it is the slowest thing here by
a wide margin, and every test wants the same two binaries.
"""

import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from src.build import BuildError, build, describe  # noqa: E402

# pytest's temporary directory is anchored inside the project: the path to the user's
# home on this platform contains an apostrophe, and the default location under it is
# not usable.
_TEMP = PROJECT / ".pytest-tmp"


def pytest_configure(config):
    _TEMP.mkdir(exist_ok=True)
    config.option.basetemp = str(_TEMP)


@pytest.fixture(scope="session")
def toolchain():
    found = describe()
    if not found["available"]:
        pytest.skip(found["reason"])
    return found


@pytest.fixture(scope="session")
def vulnerable(toolchain):
    try:
        return build(vulnerable=True)
    except BuildError as exc:
        pytest.fail("the target did not build: %s" % exc)


@pytest.fixture(scope="session")
def patched(toolchain):
    try:
        return build(vulnerable=False)
    except BuildError as exc:
        pytest.fail("the target did not build: %s" % exc)


@pytest.fixture(scope="session")
def exploit_builds(toolchain):
    return (build(vulnerable=True, exploit=True),
            build(vulnerable=False, exploit=True))


@pytest.fixture
def coverage_map():
    from src.coverage import CoverageMap
    mapping = CoverageMap("cgf-test-%d" % os.getpid())
    yield mapping
    mapping.close()


@pytest.fixture
def scratch(tmp_path):
    return tmp_path


import os  # noqa: E402
