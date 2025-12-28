"""
Steganography-based Exfiltration
Hide data in images and PDFs
"""

import io
import os
from typing import Optional
from PIL import Image
import numpy as np

class SteganographyExfil:
    """
    Exfiltrates data by hiding it in images and documents
    """
    
    def __init__(self):
        self.supported_formats = ['PNG', 'BMP', 'TIFF']
    
    def hide_in_image(self, data: bytes, cover_image_path: str, 
                      output_path: str, method: str = 'lsb') -> bool:
        """
        Hide data in an image using LSB steganography
        
        Args:
            data: Data to hide
            cover_image_path: Path to cover image
            output_path: Path to save stego image
            method: 'lsb' or 'dct'
        
        Returns: Success status
        """
        print(f"[*] Hiding {len(data)} bytes in {cover_image_path}")
        
        try:
            # Load cover image
            img = Image.open(cover_image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get image data
            img_array = np.array(img)
            
            if method == 'lsb':
                stego_array = self._lsb_encode(img_array, data)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            # Save stego image
            stego_img = Image.fromarray(stego_array.astype('uint8'), 'RGB')
            stego_img.save(output_path)
            
            # Calculate capacity
            capacity = self._calculate_capacity(img_array)
            usage = (len(data) / capacity) * 100
            
            print(f"[+] Data hidden successfully")
            print(f"    Capacity: {capacity} bytes")
            print(f"    Used: {usage:.1f}%")
            print(f"    Output: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"[!] Error hiding data: {str(e)}")
            return False
    
    def extract_from_image(self, stego_image_path: str, data_length: int) -> Optional[bytes]:
        """
        Extract hidden data from image
        """
        try:
            img = Image.open(stego_image_path)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            data = self._lsb_decode(img_array, data_length)
            
            print(f"[+] Extracted {len(data)} bytes from {stego_image_path}")
            
            return data
            
        except Exception as e:
            print(f"[!] Error extracting data: {str(e)}")
            return None
    
    def _lsb_encode(self, img_array: np.ndarray, data: bytes) -> np.ndarray:
        """
        Encode data using LSB steganography
        """
        # Flatten image array
        flat = img_array.flatten()
        
        # Add length header (4 bytes)
        data_with_header = len(data).to_bytes(4, 'big') + data
        
        # Convert data to bits
        data_bits = []
        for byte in data_with_header:
            for i in range(8):
                data_bits.append((byte >> (7 - i)) & 1)
        
        # Check capacity
        if len(data_bits) > len(flat):
            raise ValueError("Data too large for image")
        
        # Encode bits into LSBs
        for i, bit in enumerate(data_bits):
            flat[i] = (flat[i] & 0xFE) | bit
        
        # Reshape back to original shape
        return flat.reshape(img_array.shape)
    
    def _lsb_decode(self, img_array: np.ndarray, data_length: int) -> bytes:
        """
        Decode data from LSB steganography
        """
        # Flatten image
        flat = img_array.flatten()
        
        # Extract length header (32 bits)
        length_bits = [flat[i] & 1 for i in range(32)]
        length = 0
        for bit in length_bits:
            length = (length << 1) | bit
        
        # Use provided length if available, otherwise use extracted
        if data_length:
            length = data_length
        
        # Extract data bits
        total_bits = (length + 4) * 8  # +4 for length header
        data_bits = [flat[i] & 1 for i in range(32, total_bits)]
        
        # Convert bits to bytes
        data = []
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            byte = 0
            for bit in byte_bits:
                byte = (byte << 1) | bit
            data.append(byte)
        
        return bytes(data[4:])  # Skip length header
    
    def _calculate_capacity(self, img_array: np.ndarray) -> int:
        """
        Calculate steganography capacity of image
        """
        # For LSB: 1 bit per pixel channel
        total_pixels = img_array.size
        total_bits = total_pixels
        total_bytes = total_bits // 8
        
        # Reserve 4 bytes for length header
        return total_bytes - 4
    
    def hide_in_pdf(self, data: bytes, cover_pdf_path: str, 
                    output_path: str) -> bool:
        """
        Hide data in PDF file metadata or unused space
        """
        try:
            import PyPDF2
            
            # Read original PDF
            with open(cover_pdf_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                writer = PyPDF2.PdfWriter()
                
                # Copy all pages
                for page in reader.pages:
                    writer.add_page(page)
                
                # Encode data to base64 for safe storage in metadata
                import base64
                encoded = base64.b64encode(data).decode('ascii')
                
                # Add to metadata
                metadata = {
                    '/Producer': 'PyPDF2',
                    '/Custom': encoded  # Hide data here
                }
                writer.add_metadata(metadata)
                
                # Write output
                with open(output_path, 'wb') as output_file:
                    writer.write(output_file)
            
            print(f"[+] Hidden {len(data)} bytes in PDF metadata")
            print(f"    Output: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"[!] Error hiding data in PDF: {str(e)}")
            return False
    
    def extract_from_pdf(self, stego_pdf_path: str) -> Optional[bytes]:
        """
        Extract hidden data from PDF
        """
        try:
            import PyPDF2
            import base64
            
            with open(stego_pdf_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                metadata = reader.metadata
                
                if metadata and '/Custom' in metadata:
                    encoded = metadata['/Custom']
                    data = base64.b64decode(encoded)
                    
                    print(f"[+] Extracted {len(data)} bytes from PDF")
                    return data
            
            print(f"[!] No hidden data found in PDF")
            return None
            
        except Exception as e:
            print(f"[!] Error extracting from PDF: {str(e)}")
            return None
    
    def create_stego_image_from_scratch(self, data: bytes, 
                                       output_path: str,
                                       size: tuple = (800, 600)) -> bool:
        """
        Create a new image with hidden data (looks like random noise/pattern)
        """
        try:
            # Calculate required size
            required_pixels = (len(data) + 4) * 8  # +4 for header, *8 for bits
            required_size = int(np.ceil(np.sqrt(required_pixels / 3)))  # 3 channels
            
            if size[0] * size[1] * 3 < required_pixels:
                size = (required_size, required_size)
            
            # Create random image
            img_array = np.random.randint(0, 256, (size[1], size[0], 3), dtype=np.uint8)
            
            # Hide data
            stego_array = self._lsb_encode(img_array, data)
            
            # Save
            stego_img = Image.fromarray(stego_array, 'RGB')
            stego_img.save(output_path)
            
            print(f"[+] Created stego image: {output_path}")
            print(f"    Size: {size[0]}x{size[1]}")
            print(f"    Hidden data: {len(data)} bytes")
            
            return True
            
        except Exception as e:
            print(f"[!] Error creating stego image: {str(e)}")
            return False
    
    def analyze_image_capacity(self, image_path: str) -> dict:
        """
        Analyze how much data can be hidden in an image
        """
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        img_array = np.array(img)
        capacity = self._calculate_capacity(img_array)
        
        analysis = {
            'image': image_path,
            'dimensions': f"{img.size[0]}x{img.size[1]}",
            'total_pixels': img.size[0] * img.size[1],
            'capacity_bytes': capacity,
            'capacity_kb': capacity / 1024,
            'capacity_mb': capacity / (1024 * 1024)
        }
        
        return analysis
    
    def batch_hide_across_images(self, data: bytes, cover_images: list, 
                                 output_dir: str) -> int:
        """
        Split and hide data across multiple images
        """
        import math
        
        # Calculate how much data per image
        chunk_size = math.ceil(len(data) / len(cover_images))
        
        success_count = 0
        
        for i, cover_path in enumerate(cover_images):
            start = i * chunk_size
            end = min(start + chunk_size, len(data))
            chunk = data[start:end]
            
            output_path = os.path.join(output_dir, f"stego_{i}_{os.path.basename(cover_path)}")
            
            if self.hide_in_image(chunk, cover_path, output_path):
                success_count += 1
        
        print(f"[+] Hidden data across {success_count}/{len(cover_images)} images")
        
        return success_count
