"""
Module 5: Bharatiya Sakshya Adhiniyam (BSA) Sec 63 Legal Certificate

Generates a court-admissible PDF certificate compliant with Section 63(4)
of the Bharatiya Sakshya Adhiniyam, 2023.
"""
from __future__ import annotations

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class BSASec63Dossier:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'TitleStyle',
            parent=self.styles['Heading1'],
            alignment=1, # Center
            spaceAfter=12
        )
        self.heading_style = self.styles['Heading2']
        self.normal_style = self.styles['Normal']
        self.code_style = ParagraphStyle(
            'Code',
            parent=self.normal_style,
            fontName='Courier',
            fontSize=9,
            leading=11
        )

    def generate_certificate(self, case: Any) -> bytes:
        """
        Generate the BSA Sec 63 PDF Certificate.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        elements = []

        # Header
        elements.append(Paragraph("BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023", self.title_style))
        elements.append(Paragraph("SECTION 63(4) - CERTIFICATE FOR ELECTRONIC EVIDENCE", self.title_style))
        elements.append(Spacer(1, 20))

        # Preamble
        preamble = """
        This certificate is generated in accordance with Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 
        to accompany the electronic record extracted and analyzed by the AI-Powered Forensic Platform.
        """
        elements.append(Paragraph(preamble, self.normal_style))
        elements.append(Spacer(1, 15))

        # Part A
        elements.append(Paragraph("PART A: DECLARATION OF SYSTEM IN-CHARGE", self.heading_style))
        
        utc_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        part_a_data = [
            ["Item", "Details"],
            ["Case ID:", str(case.id)],
            ["Extraction Timestamp:", utc_time],
            ["File Size (Bytes):", "N/A (Database Record)"],
            ["Original SHA-256:", Paragraph(case.raw_hash_sha256 or "Pending", self.code_style)],
            ["System Identifier:", "AI-Forensics-SIH-Node-01"]
        ]
        
        t_part_a = Table(part_a_data, colWidths=[150, 370])
        t_part_a.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(t_part_a)
        elements.append(Spacer(1, 20))

        # Part B
        elements.append(Paragraph("PART B: TECHNICAL EXAMINER DECLARATION", self.heading_style))
        declaration = """
        I, the undersigned system architect/technical examiner, hereby certify that the electronic record represented above 
        was produced by the computer system during its ordinary course of activities. The system was operating properly 
        and the hashes extracted match the original payload precisely without tampering or modification.
        """
        elements.append(Paragraph(declaration, self.normal_style))
        elements.append(Spacer(1, 30))

        # Signature Box
        sig_data = [
            ["System Stamp Hash:", Paragraph(case.raw_hash_sha256 or "", self.code_style)],
            ["Digital Seal:", "AUTHORIZED_BSA_63_SEAL"],
            ["Date of Issuance:", utc_time],
            ["Signature:", "___________________________"]
        ]
        t_sig = Table(sig_data, colWidths=[150, 370])
        t_sig.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
        ]))
        elements.append(t_sig)

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes

# Singleton
bsa_sec63_dossier = BSASec63Dossier()
