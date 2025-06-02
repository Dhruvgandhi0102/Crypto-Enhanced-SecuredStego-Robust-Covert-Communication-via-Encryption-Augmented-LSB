# Crypto-Enhanced SecuredStego: LSB Steganography with Byte Shift Cipher

## Project Overview

This project implements a robust steganography tool that utilizes the Least Significant Bit (LSB) technique to hide secret messages within image files. To enhance security, the hidden messages are first encrypted using a simple Byte Shift Cipher before being embedded. The application provides a user-friendly graphical interface built with Tkinter, allowing for seamless embedding and extraction operations.

A key feature of this tool is its ability to perform **bit-level classification evaluation** after extraction, providing metrics such as True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN), Precision, Recall, and F1-Score. This helps quantify the accuracy of the steganography process at the binary level.

## Features

* **LSB Steganography:** Embeds secret messages into the least significant bits of the RGB channels of PNG images.
* **Byte Shift Cipher Encryption:** Encrypts the secret message before embedding, adding a layer of cryptographic security. The same key is required for decryption.
* **Message Length Prefix:** Automatically embeds the length of the encrypted message as a 32-bit prefix, allowing accurate extraction.
* **User-Friendly GUI:** Intuitive interface built with Tkinter for easy embedding and extraction.
* **Bit-Level Evaluation Metrics:** Calculates and displays:
    * **True Positives (TP):** Bits that were 1 in the original message and extracted as 1.
    * **False Positives (FP):** Bits that were 0 in the original message but extracted as 1.
    * **False Negatives (FN):** Bits that were 1 in the original message but extracted as 0.
    * **True Negatives (TN):** Bits that were 0 in the original message and extracted as 0.
    * **Precision:** The proportion of positive identifications that were actually correct.
    * **Recall:** The proportion of actual positives that were correctly identified.
    * **F1-Score:** The harmonic mean of Precision and Recall, providing a balance between them.
* **Error Handling:** Robust error handling for file operations, message length, and invalid keys.

## Core Concepts

* **Steganography:** The art and science of hiding communication in plain sight. LSB (Least Significant Bit) steganography involves altering the least significant bits of pixel color values, which are imperceptible to the human eye, to store data.
* **Byte Shift Cipher:** A simple substitution cipher where each byte in the message is shifted by a fixed numeric value (the key) modulo 256. This is similar to a Caesar cipher but operates on byte values (0-255) instead of alphabet letters.
* **PNG Format:** PNG is a lossless image format, crucial for LSB steganography as it preserves the exact pixel data without introducing compression artifacts that would destroy the hidden message.

## File Structure

MyStegoProject/
├── cipher_utils.py
├── steganography_backend.py
├── steganography_frontend.py
└── README.md


* `cipher_utils.py`: Contains utility functions for binary conversion and the `byte_shift_cipher` implementation (encryption/decryption).
* `steganography_backend.py`: Implements the core LSB embedding and extraction algorithms. It utilizes `cipher_utils` for encryption/decryption and provides the `calculate_bit_metrics` function for evaluation.
* `steganography_frontend.py`: Provides the Tkinter-based graphical user interface (GUI) for the application. It acts as the bridge between user interaction and the backend logic.
* `README.md`: This file, providing an overview and instructions for the project.

## How to Run the Application

### Prerequisites

* Python 3.x installed.
* `Pillow` library: `pip install Pillow` (for image manipulation).

### Steps

1.  **Clone the Repository (or Download):**
    If you haven't already, clone this repository to your local machine:
    ```bash
    git clone [https://github.com/YourGitHubUsername/YourRepoName.git](https://github.com/YourGitHubUsername/YourRepoName.git)
    cd YourRepoName
    ```
    *(Replace `YourGitHubUsername` and `YourRepoName` with your actual GitHub username and repository name.)*

2.  **Install Dependencies:**
    Open your terminal or command prompt, navigate to the project directory, and install the `Pillow` library:
    ```bash
    pip install Pillow
    ```

3.  **Run the Frontend:**
    Execute the frontend script:
    ```bash
    python steganography_frontend.py
    ```

    A graphical window will appear, ready for use.

## Usage Example

1.  **Embed Message:**
    * Click "Browse..." next to "Input Image (PNG)" and select a PNG image.
    * Type your secret message into the "Secret Message" text area.
    * Enter an integer key in "Encryption Key" (e.g., `13`).
    * Click "Browse..." next to "Output Image (PNG)" to choose where to save the stego-image (ensure it ends with `.png`).
    * Click "Embed Message". A success message will appear in the "Status / Output" section.

2.  **Extract Message:**
    * Click "Browse..." next to "Stego Image (PNG)" and select the image you previously embedded a message into (e.g., `stego_output.png`).
    * Enter the **exact same encryption key** you used during embedding.
    * Click "Extract Message".
    * The extracted decrypted message and bit-level metrics (if applicable, i.e., embedded and extracted in the same session) will appear in the "Status / Output" section.

## Limitations

* **PNG-Only:** The LSB method is most effective and reliable with lossless PNG images. Using JPEG or other lossy formats will likely corrupt the hidden message.
* **Message Capacity:** The size of the secret message is limited by the dimensions of the cover image. Larger images can hide more data.
* **Simple Cipher:** The Byte Shift Cipher is for demonstration purposes. For high-security applications, more robust encryption algorithms would be necessary.
* **Session-based Metrics:** Bit-level metrics (Precision, Recall, F1-Score) are accurate only if the original message was embedded within the current application session, as the original binary string is stored in memory.