# ai_key_generator.py - Using Google Gemini API

import requests # Required for making HTTP requests to the Gemini API

def generate_ai_cipher_key() -> int:
    """
    Generates a random integer key for the byte shift cipher (0-255)
    by making a call to the Google Gemini API.

    Returns:
        int: A valid integer key between 0 and 255 (inclusive).

    Raises:
        ValueError: If the API key is not set, the API call fails,
                    or the AI returns an invalid key/response structure.
    """
    # !!! IMPORTANT: PASTE YOUR GEMINI API KEY HERE !!!
    # Replace "YOUR_GEMINI_API_KEY_HERE" with the actual key you copied from Google AI Studio.
    # Example: GEMINI_API_KEY = "AIzaSyC-b1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6"
    #
    # This string below should contain your actual, secret Gemini API key.
    GEMINI_API_KEY = "AIzaSyCxgIA_AF22iplIruwmJSqrVDdiNjON1WQ" 
    
    # This check ensures that the user has replaced the placeholder with their actual key.
    # If the key is still the placeholder string OR if it's an empty string, it raises an error.
    if GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE" or not GEMINI_API_KEY:
        raise ValueError(
            "Gemini API key is not set. Please update 'GEMINI_API_KEY' in ai_key_generator.py with your key."
        )

    # Define the API endpoint URL for the Gemini 2.0 Flash model.
    # This URL is used to send requests to Google's AI service.
    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
    
    # Define the prompt (instruction) to send to the AI model.
    # We explicitly ask for a single integer between 0 and 255 with no extra text.
    prompt_content = "Generate a single random integer between 0 and 255, inclusive. Only output the integer, no other text, explanation, or punctuation. Make it truly random."
    
    # Structure the chat history as required by the Gemini API.
    # In this case, it's a single user message.
    chat_history = []
    chat_history.append({"role": "user", "parts": [{"text": prompt_content}]})

    # Define the payload (data) to send in the API request.
    # It includes the chat history and generation configuration.
    payload = {
        "contents": chat_history,
        "generationConfig": {
            "responseMimeType": "text/plain", # Request the AI's response as plain text.
            "temperature": 1.0,               # <--- IMPORTANT: This increases randomness.
        }
    }

    try:
        # Send the POST request to the Gemini API.
        response = requests.post(apiUrl, json=payload)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx status codes).

        # Parse the JSON response received from the API.
        result = response.json()

        # Safely access the generated text from the API response structure.
        # This checks for the existence of nested keys to prevent errors if the response is unexpected.
        if "candidates" in result and len(result["candidates"]) > 0 and \
           "content" in result["candidates"][0] and "parts" in result["candidates"][0]["content"] and \
           len(result["candidates"][0]["content"]["parts"]) > 0:
            
            # Extract and clean up the generated text (remove leading/trailing whitespace).
            text = result["candidates"][0]["content"]["parts"][0]["text"].strip()
            
            # Attempt to convert the extracted text (which should be a number string) into an integer.
            try:
                parsed_key = int(text)
            except ValueError:
                # If the AI did not generate a valid integer (e.g., generated words instead of a number), raise an error.
                raise ValueError(f"AI generated non-integer text: '{text}'. Please try again.")

            # Validate that the parsed integer is within the expected range [0, 255] for the cipher key.
            if 0 <= parsed_key <= 255:
                return parsed_key # Return the valid generated key.
            else:
                # If the AI generated an integer outside the specified range, raise an error.
                raise ValueError(f"AI generated key {parsed_key} which is out of range [0-255]. Please try again.")
        else:
            # If the Gemini API response structure is unexpected or empty (e.g., no generated content), raise an error.
            raise ValueError("Gemini API did not return a valid content structure. Please try again.")

    except requests.exceptions.RequestException as e:
        # Catch network-related errors (e.g., no internet connection) or HTTP errors from the API call.
        raise ValueError(f"API request failed: {e}. Check internet connection or API key.")
    except Exception as e:
        # Catch any other unexpected exceptions that might occur during the process.
        raise ValueError(f"An unexpected error occurred during AI key generation: {e}")