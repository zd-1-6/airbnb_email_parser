# airbnb_eml_to_sql.py
import argparse
import datetime
import glob
import os
import re
import sys
import base64
import json
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    GMAIL_AVAILABLE = True
except ImportError:
    GMAIL_AVAILABLE = False

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate with Gmail API using OAuth2"""
    if not GMAIL_AVAILABLE:
        print("Gmail libraries not available. Install with: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        return None
    
    creds = None
    token_file = 'token.json'
    
    # Load existing credentials
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    
    # If no valid credentials, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Check for credentials.json file
            if not os.path.exists('credentials.json'):
                print("Gmail credentials not found. Please follow these steps:")
                print("1. Go to https://console.developers.google.com/")
                print("2. Create a new project or select existing one")
                print("3. Enable Gmail API")
                print("4. Create OAuth 2.0 credentials (Desktop application)")
                print("5. Download credentials.json and place in this directory")
                return None
            
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save credentials for next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
    
    return creds

def get_gmail_service():
    """Get authenticated Gmail service"""
    creds = authenticate_gmail()
    if not creds:
        return None
    
    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception as e:
        print(f"Error creating Gmail service: {e}")
        return None

def search_airbnb_emails(service):
    """Search for unread Airbnb confirmation emails"""
    try:
        # Search for unread emails from automated@airbnb.com with subject containing 'Reservation confirmed -'
        query = 'from:automated@airbnb.com subject:"Reservation confirmed -" is:unread'
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        
        if not messages:
            print("No unread Airbnb confirmation emails found.")
            return []
        
        print(f"Found {len(messages)} unread Airbnb confirmation email(s)")
        return messages
    except HttpError as error:
        print(f"Error searching emails: {error}")
        return []

def get_email_content(service, message_id):
    """Get email content by message ID"""
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        raw_data = message['raw']
        msg_bytes = base64.urlsafe_b64decode(raw_data)
        return BytesParser(policy=policy.default).parsebytes(msg_bytes)
    except HttpError as error:
        print(f"Error getting email content: {error}")
        return None

def ask_gmail_permission():
    """Ask user for permission to connect to Gmail"""
    print("This script can connect to your Gmail account to fetch Airbnb confirmation emails.")
    print("This requires Gmail API access and will open a browser window for authentication.")
    response = input("Do you want to connect to Gmail? (y/n): ").lower().strip()
    return response in ['y', 'yes']

def get_gmail_credentials():
    """Get Gmail credentials from user"""
    print("\nGmail Authentication Setup:")
    print("1. Go to https://console.developers.google.com/")
    print("2. Create a new project or select existing one")
    print("3. Enable Gmail API")
    print("4. Create OAuth 2.0 credentials (Desktop application)")
    print("5. Download credentials.json and place in this directory")
    print("\nPress Enter when you have placed credentials.json in this directory...")
    input()

# ... existing code ...

def html_to_text(html: str) -> str:
    if not html:
        return ""
    if BeautifulSoup is None:
        t = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", html, flags=re.I)
        t = re.sub(r"<br\s*/?>", "\n", t, flags=re.I)
        t = re.sub(r"</p>", "\n\n", t, flags=re.I)
        t = re.sub(r"<[^>]+>", " ", t)
        return re.sub(r"[ \t]+", " ", t)
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.extract()
    text = soup.get_text(separator="\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def message_to_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    if isinstance(payload, (bytes, bytearray)):
                        payload = payload.decode(errors="ignore")
                if not isinstance(payload, str):
                    continue
                parts.append(html_to_text(payload) if ctype == "text/html" else payload)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            if isinstance(payload, (bytes, bytearray)):
                payload = payload.decode(errors="ignore")
        if isinstance(payload, str):
            parts.append(html_to_text(payload) if ctype == "text/html" else payload)
    return "\n\n".join(p.strip() for p in parts if isinstance(p, str) and p.strip())

def parse_booked_at(date_header: str) -> str:
    if not date_header:
        return ""
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        dt_utc = dt.astimezone(datetime.timezone.utc)
        return dt_utc.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

def parse_date_token(s: str) -> str:
    m = re.search(r"\b([A-Za-z]{3,9})\s+(\d{1,2})(?:,?\s*(\d{4}))?\b", s)
    if not m:
        return ""
    month, day, year = m.group(1), m.group(2), m.group(3)
    if not year:
        m2 = re.search(r"\b(20\d{2})\b", s)
        year = m2.group(1) if m2 else str(datetime.datetime.utcnow().year)
    try:
        dt = datetime.datetime.strptime(f"{month} {day} {year}", "%b %d %Y")
    except ValueError:
        try:
            dt = datetime.datetime.strptime(f"{month} {day} {year}", "%B %d %Y")
        except ValueError:
            return ""
    return dt.strftime("%Y-%m-%d") + " 00:00:00"

def find_confirmation_code(text: str) -> str:
    for pat in [
        r"\bCONFIRMATION CODE\s*\n([A-Z0-9]{6,})\b",
        r"\bConfirmation(?:\s+Code)?\s*[:\-]?\s*([A-Z0-9]{6,})\b",
        r"\bReservation(?:\s+Code)?\s*[:\-]?\s*([A-Z0-9]{6,})\b",
    ]:
        m = re.search(pat, text, flags=re.I)
        if m:
            return m.group(1).upper()
    return ""

def find_dates(text: str) -> tuple[str, str]:
    # Normalize non-breaking spaces
    text_norm = text.replace("\u00A0", " ")

    # Helper: extract first two date tokens from a string
    def first_two_date_tokens(s: str) -> tuple[str, str]:
        tokens = re.findall(r"([A-Za-z]{3,9}\s+\d{1,2}(?:,?\s*\d{4})?)", s)
        if len(tokens) >= 2:
            d1 = parse_date_token(tokens[0])
            d2 = parse_date_token(tokens[1])
            if d1 and d2:
                return d1, d2
        return "", ""

    # Case 1: Dates appear on the same line under a Check-in/Checkout header block
    blk = re.search(r"Check[ \-]?in[\s\S]{0,120}?\n([^\n]+)\n", text_norm, flags=re.I)
    if blk:
        d1, d2 = first_two_date_tokens(blk.group(1))
        if d1 and d2:
            return d1, d2

    # Case 2: Explicit next-line labels (legacy)
    m_in = re.search(r"\bCheck[\-\s]?in\b.*?\n([^\n]+)", text_norm, flags=re.I)
    m_out = re.search(r"\bCheck[\-\s]?out\b.*?\n([^\n]+)", text_norm, flags=re.I)
    start = parse_date_token(m_in.group(1)) if m_in else ""
    end = parse_date_token(m_out.group(1)) if m_out else ""
    if start and end:
        return start, end

    # Case 3: Any single line with two date tokens
    for line in text_norm.splitlines():
        d1, d2 = first_two_date_tokens(line)
        if d1 and d2:
            return d1, d2

    # Case 4: Range format with an en-dash or hyphen
    mr = re.search(
        r"([A-Za-z]{3,9}\s+\d{1,2},?\s*\d{4})\s*[–\-to]+\s*([A-Za-z]{3,9}\s+\d{1,2},?\s*\d{4})",
        text_norm,
        flags=re.I,
    )
    if mr:
        return parse_date_token(mr.group(1)), parse_date_token(mr.group(2))

    return "", ""

def find_guest_breakdown(text: str) -> tuple[int, int, int]:
    adults = children = infants = 0
    m = re.search(r"\b(\d{1,2})\s+adults?\b", text, flags=re.I)
    if m:
        adults = int(m.group(1))
    m = re.search(r"\b(\d{1,2})\s+children?\b", text, flags=re.I)
    if m:
        children = int(m.group(1))
    m = re.search(r"\b(\d{1,2})\s+infants?\b", text, flags=re.I)
    if m:
        infants = int(m.group(1))
    return adults, children, infants

def find_nights(text: str) -> int:
    m = re.search(r"\b(\d{1,3})\s+nights?\b", text, flags=re.I)
    return int(m.group(1)) if m else 0

def money_first_number_after(label_pat: str, text: str) -> float:
    sec = re.search(label_pat, text, flags=re.I)
    if not sec:
        return 0.0
    after = text[sec.end() : sec.end() + 200]
    m = re.search(r"([\d][\d,]*\.?\d{2})", after)
    return float(m.group(1).replace(",", "")) if m else 0.0

def find_numbers(text: str) -> dict:
    per_night = 0.0
    m = re.search(r"\b([\d][\d,]*\.?\d{2})\s*(?:x|\*)\s*\d+\s+nights?\b", text, flags=re.I)
    if m:
        per_night = float(m.group(1).replace(",", ""))

    cleaning_fee = money_first_number_after(r"Short-stay cleaning fee|Cleaning fee", text)
    service_fee = money_first_number_after(r"Guest service fee|Service fee", text)
    guest_paid = money_first_number_after(r"Total\s*\(.*?\)|\bTOTAL\b", text)
    host_payout = money_first_number_after(r"You\s+earn|Host payout|Total payout", text)

    m_hsf = re.search(r"\bHost service fee.*?(-?[\d][\d,]*\.?\d{2})", text, flags=re.I)
    h_service_fee = abs(float(m_hsf.group(1).replace(",", ""))) if m_hsf else 0.0

    return dict(
        per_night=per_night,
        cleaning_fee=cleaning_fee,
        service_fee=service_fee,
        guest_paid=guest_paid,
        host_payout=host_payout if host_payout > 0 else 0.0,
        h_per_night=per_night,
        h_cleaning_fee=cleaning_fee,
        h_service_fee=h_service_fee,
    )

def find_listing_name(text: str) -> str:
    def looks_like_url_or_tracking(s: str) -> bool:
        s2 = s.strip()
        if not s2:
            return True
        if s2.startswith("[") and s2.endswith("]"):
            return True
        if "http" in s2 or "://" in s2:
            return True
        if "?c=" in s2 or "euid=" in s2 or "utm_" in s2:
            return True
        if re.search(r"[A-Za-z0-9]{8,}=[A-Za-z0-9%\-]+", s2):
            return True
        return False

    def clean_candidate(s: str) -> str:
        s = s.strip()
        s = re.sub(r"\s+", " ", s)
        return s

    # 1) Prefer the line immediately above the accommodation type
    for acc in ("Entire home/apt", "Entire place", "Private room", "Shared room"):
        m = re.search(rf"\n([^\n]{{3,160}})\n\s*{re.escape(acc)}\b", text, flags=re.I)
        if m:
            cand = m.group(1)
            if not looks_like_url_or_tracking(cand):
                return clean_candidate(cand)

    # 2) If we find a rooms URL, scan forward to the next non-empty, non-tracking line,
    #    but stop if we hit the accommodation type block.
    url = re.search(r"https?://www\.airbnb\.com/rooms/\d+", text, flags=re.I)
    if url:
        after = text[url.end(): url.end() + 1200]
        lines = [l.strip() for l in after.splitlines()]
        for line in lines:
            if re.search(r"\b(Entire home/apt|Entire place|Private room|Shared room)\b", line, flags=re.I):
                break
            if not line:
                continue
            if looks_like_url_or_tracking(line):
                continue
            return clean_candidate(line)

    # 3) Fallback: any line that sits above accommodation type within a small window
    m2 = re.search(r"\n([^\n]{3,160})\n\s*(?:Entire home/apt|Entire place|Private room|Shared room)\b", text, flags=re.I)
    if m2:
        cand = m2.group(1)
        if not looks_like_url_or_tracking(cand):
            return clean_candidate(cand)

    return ""

def find_guest_name_from_subject(subject: str) -> str:
    if not subject:
        return ""
    m = re.search(r"Reservation confirmed\s*-\s*(.+?)\s+arrives\b", subject, flags=re.I)
    if m:
        return m.group(1).strip()
    m2 = re.search(
        r"New booking confirmed!\s*([A-Za-z][\w'.-]*(?:\s+[A-Za-z][\w'.-]*)?)\s+arrives\b",
        subject,
        flags=re.I,
    )
    return m2.group(1).strip() if m2 else ""

def find_earnings_from_you_earn(text: str) -> float:
    m = re.search(r"\bYou\s+earn\b[^\d]{0,80}?([\d][\d,]*\.?\d{2})", text, flags=re.I | re.S)
    return float(m.group(1).replace(",", "")) if m else 0.0

def sql_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "''")

def build_insert(row: dict) -> str:
    cols = [
        "id",
        "booked",
        "confirmation_code",
        "contact_details",
        "earnings",
        "end_date",
        "guest_name",
        "listing_name",
        "num_adults",
        "num_children",
        "num_infants",
        "num_nights",
        "start_date",
        "reservation_status",
        "num_reviews",
        "phone",
        "guest_paid",
        "per_night",
        "cleaning_fee",
        "service_fee",
        "host_payout",
        "h_per_night",
        "h_cleaning_fee",
        "h_service_fee",
    ]
    vals = [
        "NULL",
        f"'{row.get('booked','')}'" if row.get("booked") else "NULL",
        f"'{sql_escape(row.get('confirmation_code',''))}'",
        "''",
        f"{row.get('earnings',0.0):.2f}",
        f"'{row.get('end_date','')}'" if row.get("end_date") else "'0000-00-00 00:00:00'",
        f"'{sql_escape(row.get('guest_name',''))}'" if row.get("guest_name") else "''",
        f"'{sql_escape(row.get('listing_name',''))}'" if row.get("listing_name") else "''",
        str(row.get("num_adults", 0)),
        str(row.get("num_children", 0)),
        str(row.get("num_infants", 0)),
        str(row.get("num_nights", 0)),
        f"'{row.get('start_date','')}'" if row.get("start_date") else "'0000-00-00 00:00:00'",
        "'Reservation confirmed'",
        "0",
        "''",
        f"{row.get('guest_paid',0.0):.2f}",
        f"{row.get('per_night',0.0):.2f}",
        f"{row.get('cleaning_fee',0.0):.2f}",
        f"{row.get('service_fee',0.0):.2f}",
        f"{row.get('host_payout',0.0):.2f}",
        f"{row.get('h_per_night',0.0):.2f}",
        f"{row.get('h_cleaning_fee',0.0):.2f}",
        f"{row.get('h_service_fee',0.0):.2f}",
    ]
    return "INSERT INTO `airbnb_reservations` (`" + "`, `".join(cols) + "`) VALUES\n(" + ", ".join(vals) + ");"

def parse_message(msg) -> str:
    """Parse email message object (works for both .eml files and Gmail messages)"""
    text = message_to_text(msg)
    subject = msg.get("Subject", "") or ""
    booked = parse_booked_at(msg.get("Date", ""))

    start_date, end_date = find_dates(text)
    adults, children, infants = find_guest_breakdown(text)
    nights = find_nights(text)
    nums = find_numbers(text)

    earnings = find_earnings_from_you_earn(text)
    if earnings == 0.0:
        earnings = nums.get("host_payout", 0.0)

    row = {
        "booked": booked,
        "confirmation_code": find_confirmation_code(text),
        "guest_name": find_guest_name_from_subject(subject),
        "listing_name": find_listing_name(text),
        "num_adults": adults,
        "num_children": children,
        "num_infants": infants,
        "num_nights": nights,
        "start_date": start_date,
        "end_date": end_date,
        "earnings": earnings,
        "guest_paid": nums.get("guest_paid", 0.0),
        "per_night": nums.get("per_night", 0.0),
        "cleaning_fee": nums.get("cleaning_fee", 0.0),
        "service_fee": nums.get("service_fee", 0.0),
        "host_payout": nums.get("host_payout", 0.0),
        "h_per_night": nums.get("h_per_night", 0.0),
        "h_cleaning_fee": nums.get("h_cleaning_fee", 0.0),
        "h_service_fee": nums.get("h_service_fee", 0.0),
    }
    return build_insert(row)

def parse_file(path: str) -> str:
    """Parse .eml file (legacy function)"""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parsebytes(f.read())
    return parse_message(msg)

def process_gmail_emails():
    """Process emails from Gmail"""
    if not ask_gmail_permission():
        return False
    
    if not GMAIL_AVAILABLE:
        print("Installing required Gmail libraries...")
        print("Run: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        return False
    
    if not os.path.exists('credentials.json'):
        get_gmail_credentials()
        if not os.path.exists('credentials.json'):
            print("credentials.json not found. Cannot proceed with Gmail integration.")
            return False
    
    service = get_gmail_service()
    if not service:
        return False
    
    messages = search_airbnb_emails(service)
    if not messages:
        return True
    
    print(f"\nProcessing {len(messages)} email(s)...")
    
    for i, message in enumerate(messages):
        try:
            msg = get_email_content(service, message['id'])
            if msg:
                stmt = parse_message(msg)
                sys.stdout.write(stmt)
                if i < len(messages) - 1:
                    sys.stdout.write("\n\n")
                else:
                    sys.stdout.write("\n")
        except Exception as e:
            sys.stderr.write(f"Failed to parse email {message['id']}: {e}\n")
    
    return True

def main():
    p = argparse.ArgumentParser(description="Parse Airbnb .eml files into SQL INSERTs or fetch from Gmail")
    p.add_argument("--input", "-i", nargs="*", help="Paths/globs to .eml files (optional if using Gmail)")
    p.add_argument("--gmail", "-g", action="store_true", help="Fetch emails from Gmail instead of .eml files")
    args = p.parse_args()

    # If Gmail flag is set, process Gmail emails
    if args.gmail:
        if process_gmail_emails():
            return
        else:
            sys.exit(1)
    
    # If no input files specified and no Gmail flag, ask user
    if not args.input:
        print("No input files specified. Choose an option:")
        print("1. Process .eml files (specify with --input)")
        print("2. Fetch from Gmail (use --gmail flag)")
        choice = input("Enter choice (1 or 2): ").strip()
        
        if choice == "2":
            if process_gmail_emails():
                return
            else:
                sys.exit(1)
        else:
            print("Please specify .eml files with --input or use --gmail flag")
            sys.exit(1)

    # Process .eml files (original functionality)
    tokens = []
    for token in args.input:
        if any(ch in token for ch in "*?"):
            matches = glob.glob(token, recursive=True)
            tokens.extend(matches if matches else [token])
        else:
            tokens.append(token)

    expanded = []
    for t in tokens:
        if not os.path.isdir(t):
            ap = os.path.abspath(t)
            if os.path.isfile(ap):
                expanded.append(ap)

    seen = set()
    for idx, path in enumerate(expanded):
        if path in seen:
            continue
        seen.add(path)
        try:
            stmt = parse_file(path)
            sys.stdout.write(stmt)
            sys.stdout.write("\n" if idx == len(expanded) - 1 else "\n\n")
        except Exception as e:
            sys.stderr.write(f"Failed to parse {path}: {e}\n")

if __name__ == "__main__":
    main()