# Standard Python Libraries
import csv
from hashlib import sha256
import json
from typing import Any, Dict, List
from io import StringIO


def create_checksum(input: List[Dict]) -> str:
    input_as_json = json.dumps(input)
    input_as_bytes = input_as_json.encode("utf-8")
    return sha256(input_as_bytes).hexdigest()


def json_to_csv(json_array: List[Dict[str, Any]]) -> str:
    if not json_array:
        return ""

    # Extract headers (keys) from the first object in the array
    headers = list(json_array[0].keys())

    # Prepare rows for the CSV
    rows = []
    for obj in json_array:
        row = [
            ",".join(obj[header])
            if isinstance(obj[header], list)
            else (f'"{obj[header]}"' if obj[header] is not None else '""')
            for header in headers
        ]
        rows.append(",".join(row))

    # Combine headers and rows into CSV format
    csv_data = [",".join(headers)] + rows
    return "\n".join(csv_data)



def convert_to_csv(data):
    if not data:
        raise ValueError("The data list is empty. Cannot process CSV.")

    # Extract headers from the first dictionary
    headers = data[0].keys()

    # Create a CSV in memory
    csv_buffer = StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=headers)
    writer.writeheader()
    writer.writerows(data)
    csv_data = csv_buffer.getvalue()
    csv_buffer.seek(0)

    return csv_data


def write_csv_to_file(csv_data, file_path):
    """
    Writes CSV data (string) to a file.

    Args:
        csv_data (str): CSV data as a string.
        file_path (str): Path to save the CSV file.

    Returns:
        None
    """
    try:
        with open(file_path, mode='w', encoding='utf-8') as file:
            file.write(csv_data)
        print(f"CSV data successfully written to file: {file_path}")
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")