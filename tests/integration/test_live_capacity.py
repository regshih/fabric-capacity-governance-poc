"""Explicitly enabled, read-only Azure integration test."""

import os

import pytest

from fabgov.arm import ArmClient, default_token_provider
from fabgov.capacity import CapacityClient
from fabgov.config import load_config

pytestmark = pytest.mark.integration


def _enabled():
    return os.getenv("RUN_AZURE_INTEGRATION_TESTS", "").strip().lower() == "true"


@pytest.mark.skipif(not _enabled(), reason="Set RUN_AZURE_INTEGRATION_TESTS=true explicitly.")
def test_selected_capacity_can_be_read():
    config = load_config()
    assert config.subscription_id
    client = CapacityClient(ArmClient(default_token_provider()), config.subscription_id)
    result = client.get(config.resource_group, config.capacity_name)
    assert result is not None
    assert result.state
    assert result.sku_name
