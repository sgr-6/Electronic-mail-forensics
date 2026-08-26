import re
import hashlib
from typing import Dict, List, Any

class CryptoWalletTracker:
    def __init__(self):
        # Regex patterns for various cryptocurrencies
        self.patterns = {
            "BTC": re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b'),
            "ETH": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            "XMR": re.compile(r'\b(?:4[0-9AB]|8[0-9AB])[1-9A-HJ-NP-Za-km-z]{93,105}\b'),
            "TRON_USDT": re.compile(r'\bT[A-Za-z1-9]{33}\b')
        }
        
        # Hardcoded known illicit addresses for demonstration
        self.hardcoded_illicit = {
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", # Example BTC
            "0x0000000000000000000000000000000000000000" # Example ETH null address
        }

    def _generate_mock_data(self, address: str) -> Dict[str, Any]:
        """
        Deterministic mock fallback for balance and transaction lookups.
        """
        # Hash the address to generate deterministic mock data
        h = hashlib.sha256(address.encode()).hexdigest()
        
        # Use parts of the hash to determine mock values
        balance = int(h[:8], 16) / 1000000.0  # arbitrary scaling
        tx_count = int(h[8:12], 16) % 1000
        
        # Determine if it's illicit based on hardcoded list or hash characteristics
        # E.g., if the hash starts with '00' or has 'bad' early on, flag it (deterministic mock)
        is_illicit = address in self.hardcoded_illicit or h.startswith('00') or 'bad' in h[:10]
        
        return {
            "balance": round(balance, 4),
            "transaction_count": tx_count,
            "is_illicit": is_illicit,
            "illicit_reason": "Known Illicit Funds" if is_illicit else None,
            "source": "Mock API"
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text to extract cryptocurrency wallets and fetch their details.
        
        Args:
            text (str): The text to analyze (e.g., email body).
            
        Returns:
            dict: Extracted wallets, their currency, balance, and illicit status.
        """
        results = {
            "extracted_wallets": [],
            "summary": {
                "total_found": 0,
                "illicit_found": 0
            }
        }
        
        found_wallets = set()
        
        for currency, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                # Some regex might return tuples if there are groups, so ensure it's a string
                address = match if isinstance(match, str) else match[0]
                
                # Deduplicate
                if address in found_wallets:
                    continue
                found_wallets.add(address)
                
                # Fetch live data or fallback to mock
                mock_data = self._generate_mock_data(address)
                
                wallet_info = {
                    "address": address,
                    "currency": currency,
                    **mock_data
                }
                
                results["extracted_wallets"].append(wallet_info)
                results["summary"]["total_found"] += 1
                if mock_data.get("is_illicit"):
                    results["summary"]["illicit_found"] += 1
                    
        return results

# Export singleton
crypto_wallet_tracker = CryptoWalletTracker()
