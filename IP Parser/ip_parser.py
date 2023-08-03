import json
from datetime import datetime, timedelta
import re
import csv

def create_new_csv(input_json_file, output_csv_file):
    # Read data from the input JSON file
    with open(input_json_file, 'r') as f:
        data = json.load(f)

    # Convert data dictionary to JSON string
    data_json_string = json.dumps(data)

    # Define the regular expressions to match the fields
    ip_address_pattern = r'"ip_address":\s*"([^"]*)"'
    malware_pattern = r'"malware":\s*"([^"]*)"'

    # Use findall to get the matched values
    ip_address_matches = re.findall(ip_address_pattern, data_json_string)
    malware_matches = re.findall(malware_pattern, data_json_string)

    # Create a list to store new entries
    new_entries = []

    # Check if there are any matches
    if ip_address_matches and malware_matches:
        for ip_address, malware in zip(ip_address_matches, malware_matches):
            # Create a new list with the desired format for each match
            new_entry = [
                "IPAddress",
                ip_address,
                "2023-08-31T11:11:11.0Z",
                "Block",
                "High",
                "Command & Control IPs",
                malware,
                "",
                "",
                "",
                "",
                "TRUE"
            ]
            new_entries.append(new_entry)

    # Write the new data to the output CSV file
    with open(output_csv_file, 'w', newline='') as f:
        csv_writer = csv.writer(f)
        # Write the header row
        csv_writer.writerow([
            "IndicatorType",
            "IndicatorValue",
            "ExpirationTime",
            "Action",
            "Severity",
            "Title",
            "Description",
            "RecommendedActions",
            "RbacGroups",
            "Category",
            "MitreTechniques",
            "GenerateAlert"
        ])
        # Write the data rows
        csv_writer.writerows(new_entries)

# Example usage
input_json_file = "input.json"  # Replace with the actual file path
output_csv_file = "output.csv"  # Replace with the desired output file path
create_new_csv(input_json_file, output_csv_file)
