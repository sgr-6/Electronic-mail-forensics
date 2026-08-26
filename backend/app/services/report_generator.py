"""
PDF Forensic Report Generation Service.

Uses ReportLab to generate a comprehensive, visually structured PDF report
containing all forensic intelligence gathered during analysis.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.models import EmailCase, EmailHop, Attachment, ExtractedURL

class ReportGenerator:
    """Generate PDF forensic reports from analysis data."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = self.styles['Heading1']
        self.heading_style = self.styles['Heading2']
        self.normal_style = self.styles['Normal']
        
        # Custom styles
        self.alert_style = ParagraphStyle(
            'Alert',
            parent=self.normal_style,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        )
        self.code_style = ParagraphStyle(
            'Code',
            parent=self.normal_style,
            fontName='Courier',
            fontSize=9,
            leading=11
        )

    def generate_pdf(
        self,
        case: EmailCase,
        hops: list[EmailHop],
        attachments: list[Attachment],
        urls: list[ExtractedURL]
    ) -> bytes:
        """
        Generate a PDF report as bytes for a given email case.
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        elements = []

        # 1. Header & Title
        elements.append(Paragraph(f"Forensic Intelligence Report: Case #{case.id}", self.title_style))
        elements.append(Spacer(1, 12))

        # 2. Executive Summary (Risk Score & Classification)
        elements.append(Paragraph("Executive Summary", self.heading_style))
        
        summary_data = [
            ["Risk Category:", case.risk_category or "Unknown"],
            ["Risk Score:", f"{case.risk_score}/100" if case.risk_score is not None else "N/A"],
            ["Threat Type:", case.threat_type or "None Detected"],
            ["Subject:", case.subject or "No Subject"],
            ["From:", f"{case.from_display} <{case.from_address}>"],
            ["To:", case.to_address or "Unknown"],
            ["Date:", case.date_header or "Unknown"],
        ]
        
        t = Table(summary_data, colWidths=[120, 400])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # 3. Authentication Results
        elements.append(Paragraph("Authentication Analysis", self.heading_style))
        auth_data = [
            ["Protocol", "Result"],
            ["SPF", case.spf_result.upper() if case.spf_result else "N/A"],
            ["DKIM", case.dkim_result.upper() if case.dkim_result else "N/A"],
            ["DMARC", case.dmarc_result.upper() if case.dmarc_result else "N/A"]
        ]
        
        # Color code the results
        t_auth = Table(auth_data, colWidths=[120, 400])
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]
        
        for i, row in enumerate(auth_data[1:], start=1):
            if row[1] == "PASS":
                style.append(('TEXTCOLOR', (1, i), (1, i), colors.green))
            elif row[1] == "FAIL":
                style.append(('TEXTCOLOR', (1, i), (1, i), colors.red))
                style.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))
                
        t_auth.setStyle(TableStyle(style))
        elements.append(t_auth)
        elements.append(Spacer(1, 20))

        # 4. Hop-by-Hop Trace
        elements.append(Paragraph("Network Routing Trace (Hops)", self.heading_style))
        
        if hops:
            hop_data = [["Hop", "IP Address", "Country", "ISP", "Timestamp"]]
            for hop in hops:
                hop_data.append([
                    str(hop.sequence),
                    hop.ip_address or "Unknown",
                    hop.country or ("Private" if hop.is_private else "Unknown"),
                    (hop.isp[:25] + "..") if hop.isp and len(hop.isp) > 25 else (hop.isp or ""),
                    str(hop.timestamp)[:20] if hop.timestamp else ""
                ])
                
            t_hops = Table(hop_data, colWidths=[40, 100, 100, 140, 140])
            t_hops.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(t_hops)
        else:
            elements.append(Paragraph("No routing hops identified.", self.normal_style))
            
        elements.append(Spacer(1, 20))

        # 5. Attachments
        elements.append(Paragraph("Attachments", self.heading_style))
        if attachments:
            att_data = [["Filename", "Type", "Size (bytes)", "SHA-256 Hash"]]
            for att in attachments:
                att_data.append([
                    (att.filename[:20] + "..") if len(att.filename) > 20 else att.filename,
                    (att.content_type[:15] + "..") if att.content_type and len(att.content_type) > 15 else str(att.content_type),
                    str(att.size),
                    Paragraph(att.hash_sha256 or "", self.code_style)
                ])
                
            t_atts = Table(att_data, colWidths=[120, 80, 70, 250])
            t_atts.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(t_atts)
        else:
            elements.append(Paragraph("No attachments found.", self.normal_style))
            
        elements.append(Spacer(1, 20))
        
        # 6. URLs
        elements.append(Paragraph("Extracted URLs", self.heading_style))
        if urls:
            url_data = [["Defanged URL", "Suspicious", "Reason"]]
            for u in urls:
                domain = u.domain or ""
                url_data.append([
                    Paragraph((domain[:30] + "..") if len(domain) > 30 else domain, self.code_style),
                    "Yes" if u.is_suspicious else "No",
                    Paragraph(u.suspicion_reason or "", self.normal_style)
                ])
                
            t_urls = Table(url_data, colWidths=[200, 60, 260])
            url_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]
            
            for i, row in enumerate(urls, start=1):
                if row.is_suspicious:
                    url_style.append(('TEXTCOLOR', (1, i), (1, i), colors.red))
                    url_style.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))
                    
            t_urls.setStyle(TableStyle(url_style))
            elements.append(t_urls)
        else:
            elements.append(Paragraph("No URLs found.", self.normal_style))

        # Build PDF
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes

# Singleton
report_generator = ReportGenerator()
