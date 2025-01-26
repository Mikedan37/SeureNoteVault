def mock_device_list(user_id):
    return [
        {"device_id": "1", "name": "iPhone 14", "last_used": "2025-01-25"},
        {"device_id": "2", "name": "MacBook Pro", "last_used": "2025-01-24"}
    ]

def remove_device(device_id):
    """
    Remove the specified device from the user's list.
    Replace this with actual logic.
    """
    # Example implementation (replace with real logic)
    print(f"Device {device_id} removed.")
    return True