''' 
Ariana I. Rios Montaner
Unit tests for functions in main.py

'''

import pytest
import requests
import ipaddress
from main import parser, get_rules_tmp, check_compliance  
from rule import Rule                    

## Verifying that the parser creates rule object correctly
def test_parser():
    # Sample array of data to be parsed
    sample_data = {
        "Items": [
            {
                "RuleId": "328",
                "FromPort": 80,
                "IpRanges": [
                    "192.168.1.1/24",
                    "10.0.0.0/8"
                ],
                "ToPort": 80,
                "Action": "Allow",
                "Direction": "Ingress"
            },
            {
                "RuleId": "329",
                "FromPort": 443,
                "IpRanges": [
                    "172.16.0.0/16"
                ],
                "ToPort": 443,
                "Action": "Deny",
                "Direction": "Egress"
            }
        ]
    }

    # Call the parser function
    rules = parser(sample_data)

    # Assertions to ensure the parser is working correctly
    assert len(rules) == 2  

    # First rule checks
    rule_1 = rules[0]
    assert isinstance(rule_1, Rule)
    assert rule_1.get_RuleId() == "328"
    assert rule_1.get_FromPort() == 80
    assert rule_1.get_IpRanges() == ["192.168.1.1/24", "10.0.0.0/8"]
    assert rule_1.get_ToPort() == 80
    assert rule_1.get_Action() == "Allow"
    assert rule_1.get_Direction() == "Ingress"

    # Second rule checks
    rule_2 = rules[1]
    assert isinstance(rule_2, Rule)
    assert rule_2.get_RuleId() == "329"
    assert rule_2.get_FromPort() == 443
    assert rule_2.get_IpRanges() == ["172.16.0.0/16"]
    assert rule_2.get_ToPort() == 443
    assert rule_2.get_Action() == "Deny"
    assert rule_2.get_Direction() == "Egress"

## Verifying that getRules recollects the data correctly.
def test_getRules():
    # Sample data
    data = [
        {
            "Items": [
                {
                    "RuleId": "328",
                    "FromPort": 80,
                    "IpRanges": [
                        "192.168.1.1/24",
                        "10.0.0.0/8"
                    ],
                    "ToPort": 80,
                    "Action": "Allow",
                    "Direction": "Ingress"
                }
            ],
            "LastEvaluatedKey": {"RuleId": "328"}
        },
        {
            "Items": [
                {
                    "RuleId": "329",
                    "FromPort": 443,
                    "IpRanges": [
                        "172.16.0.0/16"
                    ],
                    "ToPort": 443,
                    "Action": "Deny",
                    "Direction": "Egress"
                }
            ]
        }
    ]
    
    # Call the get_rules function with sample data
    rules = get_rules_tmp(data=data)

    # Assertions to check the function works correctly
    assert len(rules) == 2
    assert isinstance(rules[0], Rule)
    assert isinstance(rules[1], Rule)

    # Check that the rules have been parsed correctly
    assert rules[0].get_RuleId() == "328"
    assert rules[0].get_FromPort() == 80
    assert rules[0].get_IpRanges() == ["192.168.1.1/24", "10.0.0.0/8"]
    assert rules[0].get_ToPort() == 80
    assert rules[0].get_Action() == "Allow"
    assert rules[0].get_Direction() == "Ingress"

    assert rules[1].get_RuleId() == "329"
    assert rules[1].get_FromPort() == 443
    assert rules[1].get_IpRanges() == ["172.16.0.0/16"]
    assert rules[1].get_ToPort() == 443
    assert rules[1].get_Action() == "Deny"
    assert rules[1].get_Direction() == "Egress"

    # Check that the data was processed correctly
    assert len(data) == 2

# Sample data for testing
compliant_rules = [
    Rule("102", 
         24, ["236.216.246.119/23", "239.76.10.8/30", "171.105.75.117/18", 
              "140.242.38.166/25", "234.110.26.180/27"], 24, "Deny", "Ingress"),
    Rule("228", -1, ["102.109.253.76/5", "78.76.115.63/14", "114.131.46.115/30", "221.98.94.123/22",
                     "101.230.123.234/13"], -1, "Allow", "Ingress"),
    Rule("328", 1024, ["79.65.186.9/18", "124.247.54.57/24", "7.79.203.224/16"],
         49151, "Deny", "Ingress"),
    Rule("99", 80, ["67.44.208.193/30"], 80, "Deny", "Egress")
]

non_compliant_rules = [
    Rule("101", 
        22,
        ["236.216.246.119/23", "239.76.10.8/30", "171.105.75.117/18", 
        "140.242.38.166/25", "234.110.26.180/27"], 23, "Allow", "Ingress"),
    Rule("103", 
         23, 
         ["236.216.246.119/23", "239.76.10.8/30", "171.105.75.117/18", 
          "140.242.38.166/25", "234.110.26.180/27"], 22, "Allow", "Ingress"),
    Rule("440", 80, ["138.25.47.147/7", "239.172.158.124/3", "131.52.42.69/20"],
         80, "Allow", "Ingress")
]

## Test compliant rules sample
def test_compliant_rules():
    result = check_compliance(compliant_rules)
    expected_result = {
        "102": "COMPLIANT",
        "228": "COMPLIANT",
        "328": "COMPLIANT",
        "99": "COMPLIANT"
    }
    assert result == expected_result

## Test non-compliant rules sample
def test_non_compliant_rules():
    result = check_compliance(non_compliant_rules)
    expected_result = {
        "101": "NON_COMPLIANT",
        "103": "NON_COMPLIANT",
        "440": "NON_COMPLIANT"
    }
    assert result == expected_result

## Test both samples
def test_mixed_rules():
    mixed_rules = compliant_rules + non_compliant_rules
    result = check_compliance(mixed_rules)
    expected_result = {
        "102": "COMPLIANT",
        "228": "COMPLIANT",
        "328": "COMPLIANT",
        "99" : "COMPLIANT",
        "101": "NON_COMPLIANT",
        "103": "NON_COMPLIANT",
        "440": "NON_COMPLIANT"
    }
    assert result == expected_result

    