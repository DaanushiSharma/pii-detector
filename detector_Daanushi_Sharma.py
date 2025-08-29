import sys, re, json, csv, ast
from typing import Dict, Any, List, Tuple

pat_email = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
pat_ip = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
pat_passport = re.compile(r'\b([A-PR-WYa-pr-wy][0-9]{7})\b')
pat_aadhar = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
pat_phone = re.compile(r'(?<!\d)(\d{10})(?!\d)')
pat_upi = re.compile(r'\b([A-Za-z0-9._-]{2,})@([A-Za-z][A-Za-z0-9._-]{1,})\b')

upi_known = {
    "upi","ybl","ibl","oksbi","okhdfcbank","okicici","okaxis","okyesbank",
    "apl","axl","sbi","paytm","ptsbi","jupiter","airtel","yapl",
    "hsbc","freecharge","mobikwik","gpay"
}

key_groups = {
    "phone": {"phone","mobile","contact","alt_phone"},
    "aadhar": {"aadhar","aadhaar","aadhar_number","aadhaar_number","address_proof"},
    "passport": {"passport","passport_no","passport_number"},
    "upi": {"upi","upi_id","vpa"},
    "name": {"name"},
    "fname": {"first_name"},
    "lname": {"last_name"},
    "email": {"email","username"},
    "address": {"address","address_line","street"},
    "city": {"city"},
    "state": {"state"},
    "pin": {"pin_code","pincode","zip","zipcode","postal_code"},
    "device": {"device_id","device","android_id","ios_id"},
    "ip": {"ip","ip_address"}
}

def parse_json(txt: str) -> Dict[str, Any]:
    if not txt:
        return {}
    try:
        return json.loads(txt.strip())
    except:
        try:
            return ast.literal_eval(txt.strip())
        except:
            try:
                return json.loads(txt.replace("'", '"'))
            except:
                return {}

def hide_phone(text: str) -> str:
    return pat_phone.sub(lambda m: m.group(1)[:2] + "XXXXXX" + m.group(1)[-2:], text)

def only_digits(s: str) -> str:
    return re.sub(r'\D', '', s)

def hide_aadhar(txt: str) -> str:
    raw = only_digits(txt)
    return " ".join([("X"*8 + raw[-4:])[i:i+4] for i in range(0, 12, 4)]) if len(raw) == 12 else txt

def hide_passport(txt: str) -> str:
    return "[REDACTED_PII]"

def hide_upi(txt: str) -> str:
    return pat_upi.sub(lambda m: m.group(1)[:2] + "****@" + m.group(2) if m.group(2).lower() in upi_known else m.group(0), txt)

def hide_email(txt: str) -> str:
    return pat_email.sub(lambda m: m.group(0).split("@")[0][:2] + "****@" + m.group(0).split("@")[1], txt)

def seems_name(val: str) -> bool:
    if not isinstance(val, str):
        return False
    parts = [x for x in re.split(r'\s+', val.strip()) if re.fullmatch(r"[A-Za-z.\-']{2,}", x)]
    return len(parts) >= 2

def mask_person(txt: str) -> str:
    return " ".join(w[0] + "X"*(len(w)-1) if len(w) > 1 else "X" for w in txt.split()) if isinstance(txt, str) else txt

def is_ip(x): return isinstance(x, str) and pat_ip.search(x)
def is_email(x): return isinstance(x, str) and pat_email.search(x)
def is_upi(x): return isinstance(x, str) and any(m.group(2).lower() in upi_known for m in pat_upi.finditer(x))
def is_phone(x): return isinstance(x, str) and pat_phone.search(x)
def is_aadhar(x): return isinstance(x, str) and (pat_aadhar.search(x) or len(only_digits(x)) == 12)
def is_passport(x): return isinstance(x, str) and pat_passport.search(x)
def is_address(x): return isinstance(x, str) and re.search(r'\d', x) and re.search(r'[A-Za-z]', x) and re.search(r'\b\d{6}\b', x)

def redact_entry(record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    flagged = False
    flags = set()
    redacted = dict(record)

    for k, v in record.items():
        lowk = str(k).lower()
        val = v if isinstance(v, str) else str(v) if v is not None else ""

        if lowk in key_groups["phone"] and is_phone(val): flagged = True
        if lowk in key_groups["aadhar"] and is_aadhar(val): flagged = True
        if lowk in key_groups["passport"] and is_passport(val): flagged = True
        if lowk in key_groups["upi"] and is_upi(val): flagged = True
        if lowk in key_groups["address"] and (is_phone(val) or is_aadhar(val) or is_upi(val)): flagged = True

        if lowk in key_groups["name"] and seems_name(val): flags.add("name")
        if lowk in key_groups["fname"] and val: flags.add("fname")
        if lowk in key_groups["lname"] and val: flags.add("lname")
        if lowk in key_groups["email"] and is_email(val): flags.add("email")
        if lowk in key_groups["address"] and is_address(val): flags.add("address")
        if lowk in key_groups["city"] and val: flags.add("city")
        if lowk in key_groups["state"] and val: flags.add("state")
        if lowk in key_groups["pin"] and re.fullmatch(r'\d{6}', str(val)): flags.add("pin")
        if lowk in key_groups["device"] and val: flags.add("device")
        if lowk in key_groups["ip"] and is_ip(val): flags.add("ip")

    if ("city" in flags and "pin" in flags) or ("city" in flags and "state" in flags):
        flags.add("address")

    score = int(("name" in flags or ("fname" in flags and "lname" in flags))) + \
            int("email" in flags) + int("address" in flags) + \
            int("device" in flags or "ip" in flags)

    final = flagged or score >= 2

    if final:
        for k, v in redacted.items():
            lowk = str(k).lower()
            val = v if isinstance(v, str) else str(v) if v is not None else ""

            if lowk in key_groups["phone"] and is_phone(val): redacted[k] = hide_phone(val)
            elif lowk in key_groups["aadhar"] and is_aadhar(val): redacted[k] = hide_aadhar(val)
            elif lowk in key_groups["passport"] and is_passport(val): redacted[k] = hide_passport(val)
            elif lowk in key_groups["upi"] and is_upi(val): redacted[k] = hide_upi(val)
            elif ("name" in flags or ("fname" in flags and "lname" in flags)) and (lowk in (key_groups["name"] | key_groups["fname"] | key_groups["lname"])): redacted[k] = mask_person(val)
            elif "email" in flags and lowk in key_groups["email"] and is_email(val): redacted[k] = hide_email(val)
            elif "address" in flags and (lowk in (key_groups["address"] | key_groups["city"] | key_groups["state"] | key_groups["pin"])):
                redacted[k] = re.sub(r'\d', 'X', val) if lowk in key_groups["address"] else val
            elif ("device" in flags or "ip" in flags) and lowk in (key_groups["device"] | key_groups["ip"]):
                redacted[k] = "[REDACTED_PII]"
            elif isinstance(v, str) and lowk in key_groups["address"]:
                redacted[k] = hide_phone(hide_upi(hide_aadhar(hide_passport(v))))

    return redacted, final

def run_csv(inp: str, outp: str):
    rows: List[Dict[str, Any]] = []
    with open(inp, newline='', encoding='utf-8') as f:
        read = csv.DictReader(f)
        for r in read:
            rid = r.get("record_id")
            raw = r.get("Data_json") or r.get("data_json") or ""
            parsed = parse_json(raw)
            fixed, flag = redact_entry(parsed)
            rows.append({
                "record_id": rid,
                "redacted_data_json": json.dumps(fixed, ensure_ascii=False),
                "is_pii": str(flag)
            })
    with open(outp, "w", newline='', encoding="utf-8") as f:
        write = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        write.writeheader()
        write.writerows(rows)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pii_cleaner_daanushi.py input.csv [output.csv]")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else "redacted_output_Daanushi_Sharma.csv"
    run_csv(infile, outfile)
    print(f"File saved: {outfile}")
