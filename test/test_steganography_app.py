# tests/test_steganography_app.py
import pytest
import os
from PIL import Image, ImageDraw

# --- UPDATED IMPORTS FOR SEPARATE FILES ---
# Assuming these files are in the same parent directory as the 'tests' folder
# We use a relative import to access them
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cipher_utils
import steganography_backend
# steganography_frontend is not typically tested directly in unit/integration tests
# as it's the GUI layer. We test the backend logic.

# --- Setup for tests ---
# Create a dummy image for testing on the fly
@pytest.fixture(scope="module")
def dummy_image(tmp_path_factory):
    img_dir = tmp_path_factory.mktemp("images")
    img_path = img_dir / "test_cover.png"
    img = Image.new('RGB', (100, 100), color='blue')
    draw = ImageDraw.Draw(img)
    draw.text((10,10), "TEST", fill=(255,255,255))
    img.save(img_path)
    return str(img_path)

# --- Test Cases ---

def test_byte_shift_cipher_encryption_decryption():
    original_bytes = b"Hello World!"
    key = 5
    encrypted_bytes = cipher_utils.byte_shift_cipher(original_bytes, key)
    decrypted_bytes = cipher_utils.byte_shift_cipher(encrypted_bytes, -key) # Use negative key for decryption
    assert decrypted_bytes == original_bytes, "Byte shift cipher decryption failed"

def test_bytes_to_binary_and_back():
    test_bytes = b"\x01\x02\xFF" # 00000001 00000010 11111111
    binary_str = cipher_utils.bytes_to_binary(test_bytes)
    assert binary_str == "000000010000001011111111"
    converted_back_bytes = cipher_utils.binary_to_bytes(binary_str)
    assert converted_back_bytes == test_bytes, "Binary conversion round trip failed"

def test_embed_and_extract_lsb(dummy_image, tmp_path):
    message = "Secret test message!"
    key = 10
    stego_output_path = tmp_path / "stego_image.png"

    # Embed message
    original_embedded_full_binary = steganography_backend.embed_lsb(dummy_image, message, key, str(stego_output_path))
    assert os.path.exists(stego_output_path), "Stego image was not created"

    # Extract message
    extracted_message, extracted_binary_payload = steganography_backend.extract_lsb(str(stego_output_path), key)

    assert extracted_message == message, "Extracted message does not match original"

    # Verify bit metrics (optional, but good for CI)
    # Note: original_embedded_full_binary includes the 32-bit length prefix
    # We need to compare only the payload part (after the first 32 bits)
    original_payload_binary = original_embedded_full_binary[32:]
    metrics = steganography_backend.calculate_bit_metrics(original_payload_binary, extracted_binary_payload)
    assert metrics['Precision'] == 1.0, "Bit-level Precision not 1.0 after embed/extract"
    assert metrics['Recall'] == 1.0, "Bit-level Recall not 1.0 after embed/extract"
    assert metrics['F1-Score'] == 1.0, "Bit-level F1-Score not 1.0 after embed/extract"
    assert metrics['TP'] == len(original_payload_binary), "Not all bits were true positives"


def test_embed_too_long_message(dummy_image, tmp_path):
    long_message = "A" * 10000 # Much longer than 100x100 image can hold
    key = 1
    stego_output_path = tmp_path / "long_message_stego.png"
    with pytest.raises(ValueError, match="Message is too long to embed"):
        steganography_backend.embed_lsb(dummy_image, long_message, key, str(stego_output_path))

def test_extract_invalid_key(dummy_image, tmp_path):
    message = "hello"
    embed_key = 5
    extract_key = 6 # Incorrect key
    stego_output_path = tmp_path / "stego_wrong_key.png"

    steganography_backend.embed_lsb(dummy_image, message, embed_key, str(stego_output_path))

    with pytest.raises(ValueError): # Expect an error due to incorrect length parsing
        steganography_backend.extract_lsb(str(stego_output_path), extract_key)

def test_extract_from_non_stego_image(dummy_image):
    key = 10
    with pytest.raises(ValueError): # Expect an error if no valid message is there
        steganography_backend.extract_lsb(dummy_image, key)