"""
PII Detector
Detects Personally Identifiable Information (PII) in files and data streams
"""

import re
import json
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class PIIMatch:
    """Represents a PII match"""
    pii_type: str
    value: str  # Masked value
    location: str
    line_number: int
    confidence: float
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PIIDetector:
    """
    Advanced PII detection engine
    """
    
    def __init__(self):
        # Regex patterns for various PII types
        self.patterns = {
            'ssn': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # XXX-XX-XXXX
                r'\b\d{3}\s\d{2}\s\d{4}\b',  # XXX XX XXXX
                r'\b\d{9}\b'  # XXXXXXXXX (with context)
            ],
            'credit_card': [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',  # Visa
                r'\b(?:5[1-5][0-9]{14})\b',  # Mastercard
                r'\b(?:3[47][0-9]{13})\b',  # Amex
                r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',  # Discover
            ],
            'email': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            'phone': [
                r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',  # US/International
                r'\b\d{3}-\d{3}-\d{4}\b',
                r'\b\(\d{3}\)\s?\d{3}-\d{4}\b'
            ],
            'ip_address': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IPv4
                r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'  # IPv6
            ],
            'passport': [
                r'\b[A-Z]{1,2}\d{6,9}\b'  # Generic passport format
            ],
            'drivers_license': [
                r'\b[A-Z]\d{7,8}\b',  # Generic DL format
                r'\b[A-Z]{1,2}\d{5,7}\b'
            ],
            'dob': [
                r'\b\d{2}/\d{2}/\d{4}\b',  # MM/DD/YYYY
                r'\b\d{4}-\d{2}-\d{2}\b',  # YYYY-MM-DD
                r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b'
            ],
            'bank_account': [
                r'\b\d{8,17}\b'  # Generic bank account (requires context)
            ],
            'iban': [
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'
            ],
            'medicare': [
                r'\b\d{4}-\d{3}-\d{3}-\d{1}\b',  # Medicare
                r'\b[A-Z]{3}\d{9}[A-Z]{2}\b'
            ],
            'mac_address': [
                r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
            ],
            'coordinates': [
                r'\b[-+]?\d{1,2}\.\d+,\s*[-+]?\d{1,3}\.\d+\b'  # GPS coordinates
            ]
        }
        
        # Context keywords that increase confidence
        self.context_keywords = {
            'ssn': ['social', 'security', 'ssn', 'ss#'],
            'credit_card': ['credit', 'card', 'visa', 'mastercard', 'amex', 'discover'],
            'bank_account': ['bank', 'account', 'routing', 'checking', 'savings'],
            'dob': ['birth', 'dob', 'born', 'birthday'],
            'passport': ['passport', 'travel', 'document'],
            'drivers_license': ['license', 'driver', 'dl#', 'dmv']
        }
        
        self.matches = []
    
    def scan_text(self, text: str, source: str = 'unknown') -> List[PIIMatch]:
        """
        Scan text for PII
        """
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pii_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        value = match.group()
                        
                        # Validate and calculate confidence
                        if self._validate_match(pii_type, value, line):
                            confidence = self._calculate_confidence(pii_type, value, line)
                            
                            if confidence > 0.5:  # Threshold
                                masked_value = self._mask_value(pii_type, value)
                                
                                pii_match = PIIMatch(
                                    pii_type=pii_type,
                                    value=masked_value,
                                    location=source,
                                    line_number=line_num,
                                    confidence=confidence
                                )
                                
                                self.matches.append(pii_match)
        
        return self.matches
    
    def scan_file(self, filepath: str) -> List[PIIMatch]:
        """
        Scan a file for PII
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000000)  # Read first 1MB
                return self.scan_text(content, filepath)
        except Exception as e:
            print(f"[!] Error scanning {filepath}: {str(e)}")
            return []
    
    def scan_json(self, json_data: Dict, source: str = 'json') -> List[PIIMatch]:
        """
        Recursively scan JSON data for PII
        """
        def scan_value(value, path=''):
            if isinstance(value, str):
                self.scan_text(value, f"{source}:{path}")
            elif isinstance(value, dict):
                for k, v in value.items():
                    scan_value(v, f"{path}.{k}" if path else k)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    scan_value(item, f"{path}[{i}]")
        
        scan_value(json_data)
        return self.matches
    
    def _validate_match(self, pii_type: str, value: str, context: str) -> bool:
        """
        Validate if match is likely real PII
        """
        if pii_type == 'credit_card':
            return self._luhn_check(value)
        
        elif pii_type == 'ssn':
            # Basic SSN validation
            digits = re.sub(r'\D', '', value)
            if len(digits) != 9:
                return False
            # Check for invalid SSNs
            if digits == '000000000' or digits == '123456789':
                return False
            area = int(digits[:3])
            if area == 0 or area == 666 or area >= 900:
                return False
            return True
        
        elif pii_type == 'email':
            # Basic email validation
            return '@' in value and '.' in value.split('@')[1]
        
        elif pii_type == 'ip_address':
            # IPv4 validation
            parts = value.split('.')
            if len(parts) == 4:
                try:
                    return all(0 <= int(p) <= 255 for p in parts)
                except:
                    return False
            return True
        
        return True  # Default to true for other types
    
    def _luhn_check(self, card_number: str) -> bool:
        """
        Luhn algorithm for credit card validation
        """
        digits = [int(d) for d in re.sub(r'\D', '', card_number)]
        
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return checksum % 10 == 0
    
    def _calculate_confidence(self, pii_type: str, value: str, context: str) -> float:
        """
        Calculate confidence score for PII match
        """
        confidence = 0.6  # Base confidence
        
        # Check for context keywords
        if pii_type in self.context_keywords:
            context_lower = context.lower()
            for keyword in self.context_keywords[pii_type]:
                if keyword in context_lower:
                    confidence += 0.2
                    break
        
        # Type-specific confidence adjustments
        if pii_type == 'credit_card':
            confidence = 0.95  # Luhn check passed
        
        elif pii_type == 'email':
            # Check for common domains
            if any(domain in value.lower() for domain in ['gmail', 'yahoo', 'outlook', 'hotmail']):
                confidence = 0.9
        
        elif pii_type == 'ssn':
            if re.match(r'\d{3}-\d{2}-\d{4}', value):
                confidence = 0.95  # Proper format
        
        return min(confidence, 1.0)
    
    def _mask_value(self, pii_type: str, value: str) -> str:
        """
        Mask PII value for safe display
        """
        if pii_type == 'ssn':
            return 'XXX-XX-' + value[-4:]
        
        elif pii_type == 'credit_card':
            digits = re.sub(r'\D', '', value)
            return 'XXXX-XXXX-XXXX-' + digits[-4:]
        
        elif pii_type == 'email':
            parts = value.split('@')
            if len(parts[0]) > 2:
                return parts[0][:2] + '***@' + parts[1]
            return '***@' + parts[1]
        
        elif pii_type == 'phone':
            digits = re.sub(r'\D', '', value)
            return '(XXX) XXX-' + digits[-4:]
        
        elif pii_type == 'bank_account':
            return 'XXXXXX' + value[-4:] if len(value) >= 4 else 'XXXXXX'
        
        else:
            # Generic masking - show first and last 2 chars
            if len(value) > 4:
                return value[:2] + '*' * (len(value) - 4) + value[-2:]
            return '*' * len(value)
    
    def generate_report(self) -> Dict:
        """
        Generate PII discovery report
        """
        report = {
            'total_matches': len(self.matches),
            'by_type': {},
            'by_location': {},
            'high_confidence': 0,
            'matches': []
        }
        
        for match in self.matches:
            # Count by type
            report['by_type'][match.pii_type] = report['by_type'].get(match.pii_type, 0) + 1
            
            # Count by location
            report['by_location'][match.location] = report['by_location'].get(match.location, 0) + 1
            
            # Count high confidence
            if match.confidence >= 0.8:
                report['high_confidence'] += 1
            
            # Add to matches
            report['matches'].append(match.to_dict())
        
        return report
    
    def export_results(self, output_file: str):
        """
        Export PII findings to JSON
        """
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] PII report exported to: {output_file}")
    
    def get_statistics(self) -> Dict:
        """
        Get statistical summary of PII findings
        """
        stats = {
            'total_pii_found': len(self.matches),
            'unique_types': len(set(m.pii_type for m in self.matches)),
            'unique_locations': len(set(m.location for m in self.matches)),
            'average_confidence': sum(m.confidence for m in self.matches) / len(self.matches) if self.matches else 0,
            'by_type': {}
        }
        
        for match in self.matches:
            if match.pii_type not in stats['by_type']:
                stats['by_type'][match.pii_type] = {
                    'count': 0,
                    'avg_confidence': 0,
                    'confidences': []
                }
            
            stats['by_type'][match.pii_type]['count'] += 1
            stats['by_type'][match.pii_type]['confidences'].append(match.confidence)
        
        # Calculate averages
        for pii_type in stats['by_type']:
            confidences = stats['by_type'][pii_type]['confidences']
            stats['by_type'][pii_type]['avg_confidence'] = sum(confidences) / len(confidences)
            del stats['by_type'][pii_type]['confidences']
        
        return stats
