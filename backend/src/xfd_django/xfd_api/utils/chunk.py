import sys
import json
from typing import List
def chunk_list_by_bytes(input_list: List, max_bytes: int) -> List[List]:
    """
    Splits a list into chunks where the total byte size of each chunk is less than or equal to max_bytes.

    Args:
        input_list (list): The list to be chunked.
        max_bytes (int): Maximum bytes allowed per chunk.

    Returns:
        list: A list of chunks, where each chunk is a sublist.
    """
    chunks = []
    current_chunk = []
    current_size = 0

    for item in input_list:
        # Serialize item to calculate its actual size
        try:
            item_size = len(json.dumps(item).encode('utf-8'))
        except TypeError:
            item_size = len(json.dumps(str(item)).encode('utf-8'))

        if current_size + item_size > max_bytes:
            # Start a new chunk
            chunks.append(current_chunk)
            current_chunk = []
            current_size = 0

        current_chunk.append(item)
        current_size += item_size

    # Add the last chunk if it's not empty
    if current_chunk:
        chunks.append(current_chunk)

    return chunks