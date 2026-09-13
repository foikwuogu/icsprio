import json
import os

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str):
    with open(os.path.join(FIXTURES_DIR, name), encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def kev_fixture():
    return load_fixture("kev_sample.json")


@pytest.fixture
def epss_fixture():
    return load_fixture("epss_sample.json")


@pytest.fixture
def vulnrichment_fixture():
    return load_fixture("vulnrichment_cve_sample.json")


@pytest.fixture
def attack_ics_fixture():
    return load_fixture("attack_ics_sample.json")


@pytest.fixture
def csaf_advisory_fixture():
    return load_fixture("csaf_advisory_sample.json")
