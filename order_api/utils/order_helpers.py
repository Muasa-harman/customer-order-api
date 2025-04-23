import json


def parse_order_details(details_input):
    """
    Parses order details from various input types into a JSON object.

    Args:
        details_input: The input data, which can be a JSON object, memoryview, bytes, or str.

    Returns:
        dict: Parsed JSON object.

    Raises:
        ValueError: If the input is empty or cannot be parsed as JSON.
    """
    try:
        # If the input is already a dictionary (JSON object), return it directly
        if isinstance(details_input, dict):
            print("Input is already a JSON object.")
            return details_input

        # Handle memoryview input
        if isinstance(details_input, memoryview):
            print("Memoryview detected, decoding...")
            details_input = details_input.tobytes().decode('utf-8')

        # Handle bytes input
        elif isinstance(details_input, bytes):
            print("Bytes detected, decoding...")
            details_input = details_input.decode('utf-8')

        # Convert non-string input to string
        elif not isinstance(details_input, str):
            details_input = str(details_input)

        print(f"Raw order details before parsing: {details_input}")

        # Check for empty input
        if not details_input.strip():
            raise ValueError("Empty order details")

        # Parse JSON string
        return json.loads(details_input)

    except json.JSONDecodeError as e:
        print(f"Unexpected parsing error: {e}")
        raise ValueError(f"Failed to parse order details: {str(e)}")

# import json


# def parse_order_details(details_input):
#     try:
#         if isinstance(details_input, dict):
#            print("Object is already in json object...")
#            return details_input
        
#         if isinstance(details_input, memoryview):
#             print("MemoryView detected, decoding...")
#             details_input = details_input.decode('utf-8')

#         elif isinstance(details_input, bytes):
#             print("Bytes detected, decoding...")
#             details_input = details_input.decode('utf-8')
        
#         elif not isinstance(details_input, str):
#             details_input = str(details_input)

#         print(f"Raw order details before parsing: {details_input}")
        

#         if not details_input.strip():
#             raise ValueError("Empty order details")
#         return json.loads(details_input)
#     except json.JSONDecodeError as e:
#         print(f"Unexpected parsing error: {e}")
#         raise ValueError(f"Failed to parse order details: {str(e)}")

