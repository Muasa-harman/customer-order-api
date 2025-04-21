import json

def parse_order_details(binary_data):
    try:
        decoded = binary_data.tobytes().decode('utf-8')
        return json.loads(decoded)
    except Exception as e:
        print(f"Failed to parse order details: {e}")
        return {}
