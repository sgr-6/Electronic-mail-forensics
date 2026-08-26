import os
from email.message import EmailMessage
import random
from datetime import datetime, timedelta

def create_eml(filename, subject, sender_name, sender_email, recipient, body, is_phish=False):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = recipient
    
    # Generate a realistic date within the last 30 days
    days_ago = random.randint(0, 30)
    date_val = datetime.utcnow() - timedelta(days=days_ago)
    msg['Date'] = date_val.strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    msg.set_content(body)
    
    # Add some fake routing headers to simulate hops
    if is_phish:
        msg.add_header('Received', 'from unknown (HELO mail-sender.cheap-vps.net) (45.227.253.109) by smtp-relay.gmail.com')
        msg.add_header('Received', 'from smtp-relay.gmail.com (209.85.220.41) by mx.google.com')
        msg.add_header('X-Mailer', 'PHP/5.6.0')
    else:
        msg.add_header('Received', 'from mail-out.corporate.in (115.112.90.10) by mx.google.com')
        msg.add_header('X-Mailer', 'Microsoft Outlook 16.0')
        
    with open(f"sample_emails/{filename}.eml", "wb") as f:
        f.write(bytes(msg))

# Templates
phishing_templates = [
    ("URGENT: SBI NetBanking KYC Suspension", "State Bank of India", "alert@sbi-update-kyc.in", "customer@gmail.com", 
     "Dear Customer,\n\nYour SBI NetBanking account will be suspended within 24 hours due to pending KYC verification. Please click the link below to update your PAN and Aadhaar details immediately.\n\nhttp://sbi-kyc-verify-portal.com/login\n\nRegards,\nSBI Support Team"),
    ("HDFC Bank: Suspicious Transaction Detected", "HDFC Alerts", "security@hdfc-alerts-secure.com", "user@company.in",
     "Dear Account Holder,\n\nWe detected a suspicious wire transfer of Rs. 45,000 from your account. If you did not authorize this, please login to cancel the transaction immediately: http://hdfc-cancel-txn.xyz\n\nSincerely,\nHDFC Fraud Prevention"),
    ("Income Tax Refund Initiated", "Income Tax Dept", "refunds@incometax-gov-in.org", "taxpayer@gmail.com",
     "Dear Taxpayer,\n\nYour Income Tax Refund for Assessment Year 2023-24 of Rs. 12,500 has been approved. Please verify your bank account details here to process the NEFT transfer: http://incometax-refund-portal.tk/verify\n\nRegards,\nITD Processing Center"),
    ("Action Required: EPF Account Update", "EPFO India", "no-reply@epfindia-update.in", "employee@techcorp.in",
     "Dear Member,\n\nYour UAN is deactivated due to missing Aadhaar seeding. Update credentials now to avoid penalty: http://epf-uan-kyc.com\n\nAct now."),
    ("Jio 5G Welcome Offer - Claim Now!", "Reliance Jio", "promo@jio-5g-rewards.com", "user@gmail.com",
     "Congratulations!\n\nYou have been selected for a free 1-year Jio 5G upgrade. Download the attached PDF to claim your QR code.\n\nRegards,\nJio Team")
]

bec_templates = [
    ("Confidential: Project Bharat Acquisition", "Rajesh Sharma - CEO", "ceo-office@techcorp-inc.com", "amit.verma@techcorp.in",
     "Amit,\n\nI am in a confidential meeting regarding the acquisition of Project Bharat. Do not discuss this with anyone. I need you to initiate an urgent SWIFT wire transfer of $150,000 to our legal consultant's escrow account in Dubai immediately. I will share the bank details once you confirm.\n\nRegards,\nRajesh Sharma"),
    ("URGENT: Vendor Payment Overdue", "Priya Desai - CFO", "p.desai@finance-update.com", "accounts@company.in",
     "Team,\n\nThe payment for TCS consulting services is long overdue. They are threatening to halt services. Process Rs. 5,00,000 to their new IndusInd bank account today. Details below.\nAccount: 154820019283\nIFSC: INDB0000001\n\nPriya"),
    ("Revised Bank Details for Q3 Invoice", "Sanjay Gupta (Vendor)", "sanjay.g@rk-enterprises.net", "finance@yourcompany.in",
     "Hi Team,\n\nPlease note our bank details have changed due to an internal audit. Direct all future payments, including the pending Rs. 2,50,000 invoice, to our new Kotak Mahindra account.\n\nThanks,\nSanjay"),
    ("Are you available?", "Vikram Singh (Director)", "vikram.director@gmail.com", "hr@company.in",
     "I'm caught up in a board meeting and need a quick favor. Can you arrange 10 Amazon Gift Cards of Rs 5000 each for client distribution? Send the codes directly to this email.\n\nVikram"),
    ("Strictly Confidential: Payroll Update", "Neha Kapur (HR Head)", "hr-admin@company-portal.in", "payroll@company.in",
     "Please update the salary account for employee ID 4402 to the attached SBI account starting this month. This is confidential.\n\nNeha")
]

cred_templates = [
    ("IT Helpdesk: Mandatory Password Reset", "IT Support", "helpdesk@corp-secure-login.com", "employee@company.in",
     "Dear Employee,\n\nYour corporate Office 365 password expires in 2 hours. Kindly update credentials at http://portal-office365-secure.com/login to maintain email access.\n\nIT Dept"),
    ("Aadhaar e-KYC Verification Failed", "UIDAI Support", "support@uidai-ekyc-gov.in", "citizen@gmail.com",
     "Your Aadhaar e-KYC for your mobile number failed. Login to verify your identity: http://uidai-verify-portal.xyz/login\n\nUIDAI"),
    ("Zomato Delivery Partner: Account Blocked", "Zomato Partner Support", "partners@zomato-support.co", "driver@gmail.com",
     "Your delivery partner account is temporarily blocked. Please login with your username and password to submit your RC book: http://zomato-partner-update.com\n\nZomato"),
    ("IRCTC Account Suspended", "IRCTC Admin", "admin@irctc-ticket-booking.in", "user@gmail.com",
     "Dear User,\n\nYour IRCTC account is suspended due to suspicious booking activity. Verify your password here: http://irctc-verify.tk\n\nIRCTC"),
    ("Your Netflix Subscription Expired", "Netflix India", "billing@netflix-india-support.com", "user@gmail.com",
     "Hi,\n\nWe couldn't process your payment. Update your credit card details now to continue watching: http://netflix-billing-update.com\n\nNetflix")
]

clean_templates = [
    ("Q3 Marketing Budget Approval", "Ananya Rao", "ananya.rao@company.in", "finance@company.in",
     "Hi Team,\n\nPlease find attached the approved Q3 marketing budget for the Diwali campaign. Let me know if you have any questions.\n\nBest,\nAnanya"),
    ("Meeting Minutes: Project Garuda", "Karthik Iyer", "karthik.iyer@company.in", "team@company.in",
     "Hi All,\n\nThanks for joining the kickoff call for Project Garuda. As discussed, the architecture design is due by Friday. \n\nRegards,\nKarthik"),
    ("Diwali Holiday Schedule", "HR Department", "hr@company.in", "all-employees@company.in",
     "Dear Employees,\n\nPlease note the office will remain closed on Thursday and Friday for Diwali celebrations. Wishing you and your families a joyous festival!\n\nHR Team"),
    ("Client Feedback - Reliance Retail", "Sneha Patil", "sneha.patil@company.in", "sales@company.in",
     "Hi Sales Team,\n\nThe Reliance Retail team loved the demo yesterday. They have requested a revised pricing proposal for 500 licenses. Let's discuss this at 2 PM.\n\nSneha"),
    ("Server Maintenance Notification", "IT Ops", "it-ops@company.in", "all-staff@company.in",
     "Team,\n\nThe staging server will be down for scheduled maintenance tonight from 10 PM to 2 AM IST. Please save your work.\n\nIT Support")
]

# Generate emails
all_templates = [
    (phishing_templates, "phishing", True),
    (bec_templates, "bec", True),
    (cred_templates, "cred_harvest", True),
    (clean_templates, "clean", False)
]

counter = 1
for template_group, prefix, is_phish in all_templates:
    for subject, sender_name, sender_email, recipient, body in template_group:
        filename = f"{counter:02d}_{prefix}_{sender_name.split()[0].lower()}"
        create_eml(filename, subject, sender_name, sender_email, recipient, body, is_phish)
        counter += 1

print(f"Generated {counter-1} realistic Indian sample emails in 'sample_emails/' directory.")
