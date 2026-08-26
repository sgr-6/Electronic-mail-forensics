"""
IMAP Ingester Service for direct Gmail integration.
Connects to an IMAP server (like Gmail), fetches emails, and returns raw EML bytes.
"""
from __future__ import annotations

import imaplib
import email
from typing import Any, List
import logging

logger = logging.getLogger(__name__)

class IMAPIngester:
    def __init__(self):
        pass

    def fetch_recent_emails(self, imap_server: str, email_user: str, app_password: str, limit: int = 5) -> List[bytes]:
        """
        Connects to IMAP, fetches the most recent `limit` emails, and returns their raw RFC822 bytes.
        """
        try:
            # Connect to the server
            mail = imaplib.IMAP4_SSL(imap_server)
            mail.login(email_user, app_password)
            
            # Select the inbox
            mail.select("inbox")
            
            # Search for ALL emails (you can change this to "UNSEEN" if preferred)
            status, messages = mail.search(None, "ALL")
            if status != "OK":
                logger.error("Failed to search emails.")
                return []
                
            email_ids = messages[0].split()
            # Get the most recent ones (last `limit` IDs)
            recent_ids = email_ids[-limit:]
            
            raw_emails = []
            for e_id in recent_ids:
                # Fetch the raw RFC822 message
                status, msg_data = mail.fetch(e_id, "(RFC822)")
                if status != "OK":
                    continue
                    
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email_bytes = response_part[1]
                        raw_emails.append(raw_email_bytes)
                        
            mail.logout()
            return raw_emails
            
        except Exception as e:
            logger.error(f"IMAP Fetch Error: {e}")
            raise ValueError(f"Failed to fetch emails via IMAP. Ensure IMAP is enabled and App Password is correct. Details: {e}")

# Singleton
imap_ingester = IMAPIngester()
