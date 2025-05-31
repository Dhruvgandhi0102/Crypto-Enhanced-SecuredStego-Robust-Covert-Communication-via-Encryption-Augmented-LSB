# cipher_utils.py

def bytes_to_binary(data_bytes: bytes) -> str:
    """Converts a bytes object to its binary string representation."""
    return ''.join(format(byte, '08b') for byte in data_bytes)

def binary_to_bytes(binary_string: str) -> bytes:
    """Converts a binary string back to a bytes object."""
    if len(binary_string) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8.")
    byte_array = bytearray()
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        byte_array.append(int(byte, 2))
    return bytes(byte_array)

def byte_shift_cipher(data_bytes: bytes, key: int) -> bytes:
    """
    Applies a byte shift cipher to a bytes object.
    Key can be positive (encrypt) or negative (decrypt).
    Each byte value (0-255) is shifted.
    """
    if not isinstance(key, int):
        raise ValueError("Key must be an integer.")
    
    shifted_bytes = bytearray(len(data_bytes))
    effective_key = key % 256 # Ensure key wraps around 0-255 for modular arithmetic

    for i, byte_value in enumerate(data_bytes):
        shifted_byte = (byte_value + effective_key) % 256
        shifted_bytes[i] = shifted_byte
    return bytes(shifted_bytes)