# LSB Steganography Tool Frontend using Tkinter
# This script provides a GUI for embedding and extracting messages in PNG images using LSB steganography.
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import steganography_backend
import ai_key_generator

class SteganographyApp:
    def __init__(self, master):
        self.master = master
        master.title("LSB Steganography Tool")
        master.geometry("800x700") # Set initial window size

        # Variables to hold user inputs
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()  
        self.encryption_key = tk.StringVar() # No default value # Default key for convenience because 81 is Not an Extreme, Not Round or a Multiple of 10/5, Not a "Favorite Random" and Not a Prime Number. 
        self.secret_message = tk.StringVar() # For embedding
        self.extracted_message_display = tk.StringVar() # For extracted output

        # Main Layout Frames
        self.embed_frame = tk.LabelFrame(master, text="Embed Message", padx=10, pady=10)
        self.embed_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.extract_frame = tk.LabelFrame(master, text="Extract Message", padx=10, pady=10)
        self.extract_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.status_frame = tk.LabelFrame(master, text="Status / Output", padx=10, pady=10)
        self.status_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Embeded Section Widgets 
        tk.Label(self.embed_frame, text="Input Image (PNG):").grid(row=0, column=0, sticky="w", pady=2)
        tk.Entry(self.embed_frame, textvariable=self.input_image_path, width=50).grid(row=0, column=1, pady=2)
        tk.Button(self.embed_frame, text="Browse...", command=self.browse_input_image_embed).grid(row=0, column=2, padx=5, pady=2)

        tk.Label(self.embed_frame, text="Secret Message:").grid(row=1, column=0, sticky="nw", pady=2)
        self.message_text = scrolledtext.ScrolledText(self.embed_frame, wrap=tk.WORD, width=40, height=5)
        self.message_text.grid(row=1, column=1, columnspan=2, pady=2, sticky="ew")

        tk.Label(self.embed_frame, text="Encryption Key:").grid(row=2, column=0, sticky="w", pady=2)
        tk.Entry(self.embed_frame, textvariable=self.encryption_key, width=10).grid(row=2, column=1, sticky="w", pady=2)

        tk.Label(self.embed_frame, text="Output Image (PNG):").grid(row=3, column=0, sticky="w", pady=2)
        tk.Entry(self.embed_frame, textvariable=self.output_image_path, width=50).grid(row=3, column=1, pady=2)
        tk.Button(self.embed_frame, text="Browse...", command=self.browse_output_path_embed).grid(row=3, column=2, padx=5, pady=2)

        tk.Button(self.embed_frame, text="Embed Message", command=self.embed_message_action).grid(row=4, column=0, columnspan=3, pady=10)

        # Extract Section Widgets
        tk.Label(self.extract_frame, text="Stego Image (PNG):").grid(row=0, column=0, sticky="w", pady=2)
        tk.Entry(self.extract_frame, textvariable=self.input_image_path, width=50).grid(row=0, column=1, pady=2) # Reusing input_image_path
        tk.Button(self.extract_frame, text="Browse...", command=self.browse_input_image_extract).grid(row=0, column=2, padx=5, pady=2)

        tk.Label(self.extract_frame, text="Encryption Key:").grid(row=1, column=0, sticky="w", pady=2)
        tk.Entry(self.extract_frame, textvariable=self.encryption_key, width=10).grid(row=1, column=1, sticky="w", pady=2) # Reusing encryption_key
        tk.Label(self.embed_frame, text="Encryption Key:").grid(row=2, column=0, sticky="w", pady=2)
        tk.Entry(self.embed_frame, textvariable=self.encryption_key, width=10).grid(row=2, column=1, sticky="w", pady=2)
        tk.Button(self.embed_frame, text="Generate AI Key", command=self.generate_ai_key_action).grid(row=2, column=2, padx=5, pady=2)

        tk.Button(self.extract_frame, text="Extract Message", command=self.extract_message_action).grid(row=2, column=0, columnspan=3, pady=10)

        # --- Status/Output Section Widgets ---
        tk.Label(self.status_frame, text="Message / Status:").grid(row=0, column=0, sticky="nw", pady=2)
        self.status_text = scrolledtext.ScrolledText(self.status_frame, wrap=tk.WORD, width=60, height=8, state='disabled') # 'disabled' initially
        self.status_text.grid(row=0, column=1, columnspan=2, pady=5, sticky="ew")

        # Configure column weights for resizing
        self.embed_frame.grid_columnconfigure(1, weight=1)
        self.extract_frame.grid_columnconfigure(1, weight=1)
        self.status_frame.grid_columnconfigure(1, weight=1)
        
        # Store original binary message for metric calculation during embedding
        self.original_embedded_binary_message = ""

    def update_status(self, message, append=False):
        """Updates the status text widget."""
        self.status_text.config(state='normal') # Enable editing
        if not append:
            self.status_text.delete(1.0, tk.END) # Clear existing text
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END) # Scroll to the end
        self.status_text.config(state='disabled') # Disable editing

    def browse_input_image_embed(self):
        file_path = filedialog.askopenfilename(
            title="Select Input Image (PNG)",
            filetypes=[("PNG files", "*.png")] # Only PNG files allowed, as PNG is lossless and suitable for LSB steganography. 
        )
        if file_path:
            self.input_image_path.set(file_path)
            # Suggest an output path based on input path
            dir_name = os.path.dirname(file_path)
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            self.output_image_path.set(os.path.join(dir_name, f"{name}_stego.png"))

    def browse_output_path_embed(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Stego Image As (PNG)",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if file_path:
            self.output_image_path.set(file_path)

    def browse_input_image_extract(self):
        file_path = filedialog.askopenfilename(
            title="Select Stego Image (PNG) to Extract From",
            filetypes=[("PNG files", "*.png")]
        )
        if file_path:
            self.input_image_path.set(file_path) # Update the common input path

    def embed_message_action(self):
        input_path = self.input_image_path.get()
        output_path = self.output_image_path.get()
        secret_msg = self.message_text.get(1.0, tk.END).strip() # Get text from ScrolledText
        try:
            key = int(self.encryption_key.get())
        except ValueError:
            messagebox.showerror("Invalid Key", "Encryption Key must be an integer.")
            return

        if not input_path or not output_path or not secret_msg:
            messagebox.showwarning("Missing Information", "Please fill in all fields for embedding.")
            return
        if not os.path.exists(input_path):
            messagebox.showerror("File Not Found", f"Input image not found: {input_path}")
            return

        self.update_status("Attempting to embed message...", append=False)
        try:
            # Call the backend function
            self.original_embedded_binary_message = steganography_backend.embed_lsb(input_path, secret_msg, key, output_path)
            self.update_status(f"Message successfully embedded into {output_path}", append=True)
            self.update_status(f"Original message length (bits): {len(self.original_embedded_binary_message)}", append=True)
            
            # Reset extracted message display in case it was used for extraction before
            self.extracted_message_display.set("") 
            # Clear text area after successful embed to show readiness for new message
            self.message_text.delete(1.0, tk.END)

        except ValueError as e:
            messagebox.showerror("Embedding Error", str(e))
            self.update_status(f"Embedding failed: {e}", append=False)
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred during embedding: {e}")
            self.update_status(f"Embedding failed: {e}", append=False)


    def extract_message_action(self):
        input_path = self.input_image_path.get()
        try:
            key = int(self.encryption_key.get())
        except ValueError:
            messagebox.showerror("Invalid Key", "Encryption Key must be an integer.")
            return

        if not input_path:
            messagebox.showwarning("Missing Information", "Please select a stego image for extraction.")
            return
        if not os.path.exists(input_path):
            messagebox.showerror("File Not Found", f"Stego image not found: {input_path}")
            return

        self.update_status("Attempting to extract message...", append=False)
        try:
            # Call the backend function
            decrypted_msg, extracted_encrypted_binary_message = steganography_backend.extract_lsb(input_path, key)
            self.extracted_message_display.set(decrypted_msg) # Store for potential future use (though directly displayed)
            self.update_status(f"Message extracted successfully!\n\nExtracted Message:\n{decrypted_msg}", append=True)
            
            # Display bit-level metrics if original was embedded in this session
            if self.original_embedded_binary_message and extracted_encrypted_binary_message:
                self.update_status("\n--- Bit-Level Classification Metrics ---", append=True)
                length_prefix_size_bits = 32
                original_payload_binary = self.original_embedded_binary_message[length_prefix_size_bits:]

                metrics = steganography_backend.calculate_bit_metrics(original_payload_binary, extracted_encrypted_binary_message)
                self.update_status(f"Original Embedded Payload Bits: {len(original_payload_binary)}", append=True)
                self.update_status(f"Extracted Payload Bits: {len(extracted_encrypted_binary_message)}", append=True)
                self.update_status(f"TP: {metrics['TP']}, FP: {metrics['FP']}, FN: {metrics['FN']}, TN: {metrics['TN']}", append=True)
                self.update_status(f"Precision: {metrics['Precision']:.4f}", append=True)
                self.update_status(f"Recall: {metrics['Recall']:.4f}", append=True)
                self.update_status(f"F1-Score: {metrics['F1-Score']:.4f}", append=True)
            elif self.original_embedded_binary_message:
                 self.update_status("Note: Bit metrics skipped as extracted message might be truncated/corrupted preventing full payload extraction.", append=True)
            else:
                self.update_status("Note: Bit-level metrics not available as the original message was not embedded in this session.", append=True)

        except ValueError as e:
            messagebox.showerror("Extraction Error", str(e))
            self.update_status(f"Extraction failed: {e}", append=False)
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred during extraction: {e}")
            self.update_status(f"Extraction failed: {e}", append=False)
    # ... (other methods of SteganographyApp, e.g., after extract_message_action) ...

    def generate_ai_key_action(self):
        """
        Handles the action of generating an AI key and updating the UI.
        """
        self.update_status("Generating key with AI...", append=False)
        try:
            # Call the backend function to generate the key
            ai_key = ai_key_generator.generate_ai_cipher_key()

            # Update the encryption key input field in the GUI with the new key
            self.encryption_key.set(str(ai_key)) 

            self.update_status(f"AI Generated Key: {ai_key}", append=True)
            messagebox.showinfo("AI Key Generated", f"Generated Key: {ai_key}\nUse this for embedding and extracting.")
        except ValueError as e:
            # Catch specific errors from the backend AI key generation
            messagebox.showerror("AI Key Generation Error", str(e))
            self.update_status(f"AI Key Generation failed: {e}", append=False)
        except Exception as e:
            # Catch any other unexpected errors during the process
            messagebox.showerror("Unexpected AI Error", f"An unexpected error occurred: {e}")
            self.update_status(f"AI Key Generation failed: {e}", append=False)


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()