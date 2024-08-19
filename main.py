'''
Ariana I. Rios Montaner
Coding Challenge

The following program performs a GET request to a URL containing a series of firewall rules.
The purpose is to check whether a rule is COMPLIANT or NON-COMPLIANT. 
A rule is NON-COMPLIANT if it allows ingress traffic on port 22, 80, or 443 on the IPs:
236.216.246.119, 109.3.194.189, 36.229.68.87, 21.90.154.237, 91.172.88.105

'''

import requests
import urllib.parse
import json
import ipaddress
import os
from rule import Rule

# Function to parse through each rule and convert it to a Rule object.
def parser(data):
    # Define rule array
    rules = []
    
    # Access the list of rules under "Items"
    items = data.get("Items", [])
    
    # Assign each value to a variable, create the object, and append to rule array
    for rule_data in items:
        RuleId = rule_data.get("RuleId")
        FromPort = int(rule_data.get("FromPort"))
        IpRanges = rule_data.get("IpRanges")
        ToPort = int(rule_data.get("ToPort"))
        Action = rule_data.get("Action")
        Direction = rule_data.get("Direction")
        
        rule = Rule(RuleId, FromPort, IpRanges, ToPort, Action, Direction)
        rules.append(rule)
    
    return rules

# Function to get the firewall rules from the URL or sample data (for testing)
def get_rules(url=None, data=None):
    all_rules = []  # Rule array
    last_evaluated_key = None  # Last evaluated key property
    page_count = 0  # Counter for pages (used in the testing process)

    while True:
        page_count += 1  # Increment count

        if data:  # If test data is provided, use it
            current_data = data[page_count - 1]
        else:  # Otherwise, make a real HTTP request
            if last_evaluated_key:
                # Properly convert LastEvaluatedKey to a JSON string and then URL-encode it
                json_key = json.dumps(last_evaluated_key)
                encoded_key = urllib.parse.quote(json_key)
                full_url = f"{url}?ExclusiveStartKey={encoded_key}"
            else:
                full_url = url

            # Log the request (used in the testing process)
            # print(f"Requesting page {page_count} with URL: {full_url}")

            # Make a GET request to the URL
            response = requests.get(full_url)

            # Check if the request was successful
            if response.status_code == 200:
                current_data = response.json()
            else:
                print(f"Failed to retrieve data. HTTP Status code: {response.status_code}")
                break

        # Extract and store the rules from this page
        rules = parser(current_data)
        all_rules.extend(rules)

        # Log the number of rules retrieved (used in the testing process)
        # print(f"Page {page_count} retrieved {len(rules)} rules.")

        # Check for LastEvaluatedKey to see if we need to continue
        last_evaluated_key = current_data.get("LastEvaluatedKey", None)

        if not last_evaluated_key:
            break

    # Log the total number of rules retrieved (used in testing process)
    # print(f"Total number of rules retrieved: {len(all_rules)}")

    return all_rules

# Calls the get_rules function with sample data or the URL
def get_rules_tmp(url=None, data=None):
    return get_rules(url=url, data=data)

# Verifies the compliance of each rule in the array and returns a dictionary
# with the rule ID and compliancy.
def check_compliance(rules):
    # List of non_compliant IPs
    restricted_ips = [
        "236.216.246.119", "109.3.194.189", 
        "36.229.68.87", "21.90.154.237", "91.172.88.105"
    ]
    # List of ports to flag
    restricted_ports = [22, 80, 443, -1]
    
    # Convert non-compliant IPs to ipaddress objects
    restricted_ips = [ipaddress.ip_address(ip) for ip in restricted_ips]
    
    # Dictionary with results
    compliance_results = {}
    
    # Iterate through rules
    for rule in rules:
        rule_id = rule.get_RuleId()
        from_port = rule.get_FromPort()
        to_port = rule.get_ToPort()
        ip_ranges = rule.get_IpRanges()
        direction = rule.get_Direction()
        action = rule.get_Action()
        
        # Check for compliance 
        # If the direction is "Ingress" and the action is "Allow", keep checking
        # to see if the rule is compliant
        if direction == "Ingress" and action == "Allow":
            # If the fromPort or the toPort is 22, 80, 443, or -1, keep 
            # checking if the rule is compliant
            if (from_port in restricted_ports):
                # Iterate through the range of the ips in the rule
                for cidr in ip_ranges:
                    try:
                        # Convert the ip address in the rule to a range of IP
                        # addresses, if any of these IPs falls in the range of
                        # restricted ips, the rule is non-compliant.
                        network = ipaddress.ip_network(cidr, strict=False)
                        if any(ip in network for ip in restricted_ips):
                            compliance_results[rule_id] = "NON_COMPLIANT"
                            break
                    except ValueError as e:
                        # Handle invalid CIDR notation, if needed
                        raise ValueError(f"Invalid CIDR notation error: {e}")
        # Rule is compliant
                else:
                    # If none of the non-compliant IPs fall within the range
                    compliance_results[rule_id] = "COMPLIANT"
            else:
                compliance_results[rule_id] = "COMPLIANT"
        else:
            compliance_results[rule_id] = "COMPLIANT"
    
    return compliance_results

# Writes the results into a file in the current working directory.
def write_file(compliance_results, filename):
    # Transform the dictionary to the list of dictionaries format
    compliance_list = [{"RuleId": rule_id, "Compliance": compliance}
                       for rule_id, compliance in compliance_results.items()]
    
    current_directory = os.getcwd()
    file_path = os.path.join(current_directory, filename)
    
    # Write the list to a JSON file
    with open(file_path, 'w') as json_file:
        json.dump(compliance_list, json_file, indent=2)
    
    print(f"File saved to: {file_path}")

def main(): 
    url = "https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules"
    
    # Retrieve rules 
    rules = get_rules_tmp(url)
    
    # Check the compliance of each rule
    results = check_compliance(rules)
    
    # Write results onto file
    filename = "output"
    write_file(results, filename)
    
main()
