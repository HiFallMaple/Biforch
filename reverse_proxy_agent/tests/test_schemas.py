import pytest
from pydantic import ValidationError
from reverse_proxy_agent.schemas import RuleIn


def test_rulein_validation_valid_and_invalid():
    # valid case
    valid = RuleIn(action='pass', ip='10.0.0.0/24')
    assert valid.action == 'pass'

    # invalid action
    with pytest.raises(ValidationError):
        RuleIn(action='drop', ip='10.0.0.1')
