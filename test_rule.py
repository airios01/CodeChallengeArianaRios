import pytest 
from rule import Rule

## Testing the rule class functions
class TestRule:

    ## Verifies rule is created correctly.
    def test_valid_rule_creation(self):
        rule = Rule(
            RuleId="228",
            FromPort=22,
            IpRanges=[
                "236.216.246.119/23",
                "239.76.10.8/30",
                "171.105.75.117/18",
                "140.242.38.166/25",
                "234.110.26.180/27"
            ],
            ToPort=22,
            Action="Allow",
            Direction="Ingress"
        )
        assert rule.get_RuleId() == "228"
        assert rule.get_FromPort() == 22
        assert rule.get_IpRanges() == [
            "236.216.246.119/23",
            "239.76.10.8/30",
            "171.105.75.117/18",
            "140.242.38.166/25",
            "234.110.26.180/27"
        ]
        assert rule.get_ToPort() == 22
        assert rule.get_Action() == "Allow"
        assert rule.get_Direction() == "Ingress"

    ## Verifies that an error is raised if action isn't "Allow" or "Deny".
    def test_invalid_action(self):
        with pytest.raises(ValueError, match='Action must be either "Allow" or "Deny"'):
            Rule(
                RuleId="229",
                FromPort=80,
                IpRanges=["192.168.1.0/24"],
                ToPort=80,
                Action="Block",  # Invalid action
                Direction="Ingress"
            )

    ## Verifies that an error is raised if FromPort is not an integer.
    def test_invalid_from_port(self):
        with pytest.raises(TypeError, match="FromPort must be an integer"):
            Rule(
                RuleId="230",
                FromPort="22",  # Invalid type for FromPort
                IpRanges=["192.168.1.0/24"],
                ToPort=80,
                Action="Allow",
                Direction="Ingress"
            )

    ## Verifies that an error is raised if IpRange is not a list of strings.
    def test_invalid_ip_ranges(self):
        with pytest.raises(TypeError, match="IpRanges must be a list of strings"):
            Rule(
                RuleId="231",
                FromPort=22,
                IpRanges=["192.168.1.0/24", 12345],  # Invalid type in IpRanges
                ToPort=22,
                Action="Allow",
                Direction="Ingress"
            )

    ## Verifies that setter functions are working correctly.
    def test_setters_and_getters(self):
        rule = Rule(
            RuleId="232",
            FromPort=22,
            IpRanges=["192.168.1.0/24"],
            ToPort=22,
            Action="Allow",
            Direction="Ingress"
        )

        # Testing setters and getters
        rule.set_RuleId("233")
        assert rule.get_RuleId() == "233"

        rule.set_FromPort(80)
        assert rule.get_FromPort() == 80

        rule.set_IpRanges(["10.0.0.0/8", "234.110.26.180/27"])
        assert rule.get_IpRanges() == ["10.0.0.0/8", "234.110.26.180/27"]

        rule.set_ToPort(443)
        assert rule.get_ToPort() == 443

        rule.set_Action("Deny")
        assert rule.get_Action() == "Deny"

        rule.set_Direction("Egress")
        assert rule.get_Direction() == "Egress"

