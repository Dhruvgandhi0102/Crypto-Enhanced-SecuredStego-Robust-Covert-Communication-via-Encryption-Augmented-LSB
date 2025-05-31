# steganography_backend.py

from PIL import Image, ImageDraw
import os
import math # For isnan check

# Import functions from our custom cipher_utils module
import cipher_utils

# --- LSB Steganography Functions ---

def embed_lsb(image_path: str, secret_message: str, key: int, output_path: str) -> str:
    """
    Embeds a secret message (encrypted with byte shift cipher) into an image using LSB.
    The message length (32 bits) is embedded first.
    The output image is always saved as a PNG.
    Returns the binary string of the encrypted message (including length prefix).
    """
    try:
        img = Image.open(image_path).convert("RGB") # Ensure RGB for consistent pixel access (removes alpha if present)
    except FileNotFoundError:
        raise ValueError(f"Error: Image file not found at {image_path}")
    except Exception as e:
        raise ValueError(f"Error opening image: {e}")

    width, height = img.size
    pixels = img.load() # Load pixels for direct manipulation (read/write access)

    # 1. Encode the message string to bytes (UTF-8 recommended)
    message_bytes = secret_message.encode('utf-8')

    # 2. Encrypt the bytes using the byte shift cipher (from cipher_utils)
    encrypted_bytes = cipher_utils.byte_shift_cipher(message_bytes, key)

    # 3. Convert encrypted bytes to a full binary string (from cipher_utils)
    binary_encrypted_message = cipher_utils.bytes_to_binary(encrypted_bytes)

    # 4. Prepend message length as a 32-bit binary string (4 bytes)
    message_length_in_bits = len(binary_encrypted_message)
    length_bytes = message_length_in_bits.to_bytes(4, 'big') 
    binary_length_prefix = cipher_utils.bytes_to_binary(length_bytes) # from cipher_utils

    # The full binary message to embed includes the length prefix
    full_binary_message = binary_length_prefix + binary_encrypted_message

    # Calculate total available bits for embedding (3 LSBs per pixel: R, G, B)
    available_bits = width * height * 3

    if len(full_binary_message) > available_bits:
        raise ValueError(
            f"Message is too long to embed in this image. "
            f"Message requires {len(full_binary_message)} bits, "
            f"but only {available_bits} bits are available."
        )

    bit_index = 0
    # Iterate through each pixel's R, G, B channels to embed bits
    for y in range(height):
        for x in range(width):
            if bit_index >= len(full_binary_message):
                break # Message fully embedded, stop

            r, g, b = pixels[x, y]

            # Modify the LSB of Red channel
            if bit_index < len(full_binary_message):
                bit = int(full_binary_message[bit_index])
                r = (r & 0xFE) | bit
                bit_index += 1

            # Modify the LSB of Green channel
            if bit_index < len(full_binary_message):
                bit = int(full_binary_message[bit_index])
                g = (g & 0xFE) | bit
                bit_index += 1

            # Modify the LSB of Blue channel
            if bit_index < len(full_binary_message):
                bit = int(full_binary_message[bit_index])
                b = (b & 0xFE) | bit
                bit_index += 1
            
            pixels[x, y] = (r, g, b) # Update the pixel with modified RGB values
        if bit_index >= len(full_binary_message):
            break # Break outer loop if message is fully embedded

    img.save(output_path, "PNG") # Always save as PNG to preserve LSBs (lossless format)
    print(f"Message embedded successfully! Stego image saved to {output_path}")
    return full_binary_message # Return the full binary string used for embedding


def extract_lsb(image_path: str, key: int) -> tuple[str, str]:
    """
    Extracts a secret message (decrypts with byte shift cipher) from an image using LSB.
    Returns a tuple: (decrypted_message_string, extracted_encrypted_binary_message_string)
    """
    try:
        img = Image.open(image_path).convert("RGB")
    except FileNotFoundError:
        raise ValueError(f"Error: Image file not found at {image_path}")
    except Exception as e:
        raise ValueError(f"Error opening image: {e}")

    width, height = img.size
    pixels = img.load()

    all_extracted_lsbs = ""
    # Extract ALL possible LSBs from the entire image first
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            all_extracted_lsbs += str(r & 0x01) # LSB of Red
            all_extracted_lsbs += str(g & 0x01) # LSB of Green
            all_extracted_lsbs += str(b & 0x01) # LSB of Blue
    
    length_prefix_size_bits = 32 # The length prefix is always 32 bits

    # Check if there are enough bits to even read the length prefix
    if len(all_extracted_lsbs) < length_prefix_size_bits:
        raise ValueError(
            f"Not enough LSBs in image to extract the 32-bit length prefix. "
            f"Image might not contain a hidden message or is corrupted."
        )

    # 1. Extract the 32-bit length prefix from the beginning of all extracted LSBs
    extracted_length_binary = all_extracted_lsbs[0:length_prefix_size_bits]
    
    # Convert the 32-bit binary string back to an integer
    message_length_in_bits = int(extracted_length_binary, 2)
    print(f"DEBUG: Parsed message_length_in_bits from prefix: {message_length_in_bits}")

    # Sanity checks for the extracted length
    available_bits_in_image = width * height * 3
    if message_length_in_bits > available_bits_in_image - length_prefix_size_bits:
        raise ValueError(
            f"Extracted message length ({message_length_in_bits} bits) is impossibly large for this image, "
            f"or image is corrupted. Available data bits after length prefix: "
            f"{available_bits_in_image - length_prefix_size_bits}."
        )
    if message_length_in_bits <= 0:
        raise ValueError('Extracted message length is zero or negative. Image might not contain a valid hidden message.')

    # 2. Extract the actual message bits, immediately following the length prefix
    extracted_message_binary = all_extracted_lsbs[length_prefix_size_bits : length_prefix_size_bits + message_length_in_bits]

    # Verify that the extracted message length matches the expected length
    if len(extracted_message_binary) != message_length_in_bits:
        raise ValueError(
            f"Incomplete message extracted. Expected {message_length_in_bits} bits, "
            f"but only extracted {len(extracted_message_binary)}. Image might be corrupted."
        )

    print(f"DEBUG: Raw extracted binary message: {extracted_message_binary}")

    # 3. Convert the binary message string back to encrypted bytes (from cipher_utils)
    encrypted_bytes_from_binary = cipher_utils.binary_to_bytes(extracted_message_binary)

    # 4. Decrypt the bytes using the byte shift cipher (negative key for decryption - from cipher_utils)
    decrypted_bytes = cipher_utils.byte_shift_cipher(encrypted_bytes_from_binary, -key)

    # 5. Decode the decrypted bytes back to a string (UTF-8)
    decrypted_message = decrypted_bytes.decode('utf-8', errors='replace') 
    
    return decrypted_message, extracted_message_binary


def calculate_bit_metrics(original_binary: str, extracted_binary: str) -> dict:
    """
    Calculates Precision, Recall, and F1-score at the bit level.
    Compares two binary strings (original vs. extracted).
    
    Definition:
    - Positive (P): A bit in the original message is '1'.
    - Negative (N): A bit in the original message is '0'.
    - True Positive (TP): Original '1', Extracted '1'.
    - False Positive (FP): Original '0', Extracted '1'.
    - False Negative (FN): Original '1', Extracted '0'.
    - True Negative (TN): Original '0', Extracted '0'.
    """
    if len(original_binary) != len(extracted_binary):
        print("WARNING: Original and extracted binary strings have different lengths for metric calculation.")
        # We'll truncate to the shorter length for comparison.
        min_len = min(len(original_binary), len(extracted_binary))
        original_binary = original_binary[:min_len]
        extracted_binary = extracted_binary[:min_len]

    tp, fp, fn, tn = 0, 0, 0, 0

    for i in range(len(original_binary)):
        orig_bit = int(original_binary[i])
        extr_bit = int(extracted_binary[i])

        if orig_bit == 1 and extr_bit == 1:
            tp += 1
        elif orig_bit == 0 and extr_bit == 1:
            fp += 1
        elif orig_bit == 1 and extr_bit == 0:
            fn += 1
        elif orig_bit == 0 and extr_bit == 0:
            tn += 1

    # Calculate Precision
    # Precision = TP / (TP + FP)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0 # Avoid division by zero, if no positives predicted, assume perfect if no actual positives
    if math.isnan(precision): precision = 1.0 # Handle NaN if all relevant counts are zero (e.g. no 1s in original or extracted)

    # Calculate Recall
    # Recall = TP / (TP + FN)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0 # Avoid division by zero, if no actual positives, assume perfect recall
    if math.isnan(recall): recall = 1.0

    # Calculate F1-Score
    # F1 = 2 * (Precision * Recall) / (Precision + Recall)
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    if math.isnan(f1_score): f1_score = 0.0

    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1_score
    }


# --- Example Usage (for command-line testing) ---
if __name__ == "__main__":
    # --- Create a dummy image for testing if you don't have one ---
    dummy_image_path = "test_image.png"
    if not os.path.exists(dummy_image_path):
        img = Image.new('RGB', (100, 100), color = 'red')
        draw = ImageDraw.Draw(img)
        draw.text((10,10), "Test", fill=(0,0,0))
        img.save(dummy_image_path)
        print(f"Created a dummy '{dummy_image_path}' for demonstration.")

    # --- Configuration for Embedding and Extraction ---
    input_image_path = dummy_image_path  # Use the dummy image or replace with your own PNG path
    stego_image_path = "stego_output.png" # The output image with hidden message
    
    secret_message_to_embed = "My name is Dhruv."
    encryption_key = 13 # An integer key for the byte shift cipher

    original_full_binary_message = "" # To store the binary message used for embedding
    extracted_decrypted_message = ""
    extracted_encrypted_binary_message = "" # To store the raw binary message extracted for metric calculation

    print("\n Embedding Process")
    try:
        original_full_binary_message = embed_lsb(input_image_path, secret_message_to_embed, encryption_key, stego_image_path)
    except ValueError as e:
        print(f"Embedding Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during embedding: {e}")

    print("\n Extraction Process")
    try:
        decrypted_msg, extracted_encrypted_binary_message = extract_lsb(stego_image_path, encryption_key)
        extracted_decrypted_message = decrypted_msg # Assign to the variable for comparison
        print(f"Extracted Decrypted Message:\n{extracted_decrypted_message}")
        
        if extracted_decrypted_message == secret_message_to_embed:
            print("\nSUCCESS: Original and extracted human-readable messages match!")
        else:
            print("\nFAILURE: Original and extracted human-readable messages DO NOT match.")
            print(f"Original: '{secret_message_to_embed}'")
            print(f"Extracted: '{extracted_decrypted_message}'")
    except ValueError as e:
        print(f"Extraction Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during extraction: {e}")

    # --- Classification Evaluation Metrics (Bit Level) ---
    print("\n--- Bit-Level Classification Metrics ---")
    if original_full_binary_message and extracted_encrypted_binary_message:
        # We need to compare the binary strings of the *encrypted* message payload, after the length prefix has been handled.
        # The `embed_lsb` function now returns the full binary string *including* the length prefix.
        # The `extract_lsb` function now returns the extracted binary string *excluding* the length prefix.
        # So, for accurate comparison, we need to manually get the payload part of the original binary message.
        length_prefix_size_bits = 32
        original_payload_binary = original_full_binary_message[length_prefix_size_bits:]

        if len(original_payload_binary) > 0 and len(extracted_encrypted_binary_message) > 0:
            metrics = calculate_bit_metrics(original_payload_binary, extracted_encrypted_binary_message)
            print(f"Total Original Message Bits (payload): {len(original_payload_binary)}")
            print(f"Total Extracted Message Bits (payload): {len(extracted_encrypted_binary_message)}")
            print(f"True Positives (TP): {metrics['TP']}")
            print(f"False Positives (FP): {metrics['FP']}")
            print(f"False Negatives (FN): {metrics['FN']}")
            print(f"True Negatives (TN): {metrics['TN']}")
            print(f"Precision: {metrics['Precision']:.4f}")
            print(f"Recall: {metrics['Recall']:.4f}")
            print(f"F1-Score: {metrics['F1-Score']:.4f}")
        else:
            print("Cannot calculate metrics: Original or extracted message binary payload is empty.")
    else:
        print("Cannot calculate metrics: Embedding or Extraction did not complete successfully.")