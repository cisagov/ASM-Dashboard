from hashlib import sha256
import json
import csv
from typing import List, Dict, Any

def create_checksum(input: List[Dict]) -> str:
    input_as_json = json.dumps(input)
    input_as_bytes = input_as_json.encode('utf-8')
    return sha256(input_as_bytes).hexdigest()




def json_to_csv(json_array: List[Dict[str, Any]]) -> str:
    if not json_array:
        return ''

    # Extract headers (keys) from the first object in the array
    headers = list(json_array[0].keys())

    # Prepare rows for the CSV
    rows = []
    for obj in json_array:
        row = [
            ",".join(obj[header]) if isinstance(obj[header], list) else 
            (f'"{obj[header]}"' if obj[header] is not None else '""')
            for header in headers
        ]
        rows.append(",".join(row))

    # Combine headers and rows into CSV format
    csv_data = [",".join(headers)] + rows
    return "\n".join(csv_data)
