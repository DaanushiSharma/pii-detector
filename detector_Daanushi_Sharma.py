
import sys, re, json, csv, ast
from typing import Dict, Any, List, Tuple

email_pat = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
ip_pat = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
passport_pat = re.compile(r'\b(?:(?:[A-PR-WYa-pr-wy])[0-9]{7})\b')
aadhar_pat = re.compile(r'\b(?:\d{4}\s?\d{4}\s?\d{4})\b')
ten_digit = re.compile(r'(?<!\d)(\d{10})(?!\d)')
upi_pat = re.compile(r'\b([A-Za-z0-9._-]{2,})@([A-Za-z][A-Za-z0-9._-]{1,})\b')

upi_domains = {"upi","ybl","ibl","oksbi","okhdfcbank","okicici","okaxis","okyesbank","apl","axl","sbi",
               "paytm","ptsbi","jupiter","airtel","oksbi","okaxis","okicici","okhdfcbank","okyesbank",
               "yapl","hsbc","freecharge","mobikwik","gpay"}

keys_map = {
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


def json_parse(x: str) -> Dict[str, Any]:

    if not x: return {}
    try:
        return json.loads(x.strip())
    except:
        try:
            return ast.literal_eval(x.strip())
        except:
            try:
                return json.loads(x.replace("'", '"'))
            except:
                return {}


def obf_phone(s: str) -> str:

    return ten_digit.sub(lambda m: m.group(1)[:2] + "XXXXXX" + m.group(1)[-2:], s)


def digits_only(val: str) -> str:

    return re.sub(r'\D', '', val)


def obf_aadhar(s: str) -> str:

    raw = digits_only(s)
    return " ".join([("X"*8 + raw[-4:])[i:i+4] for i in range(0, 12, 4)]) if len(raw) == 12 else s


def obf_passport(s: str) -> str:

    return "[REDACTED_PII]"


def obf_upi(s: str) -> str:

    return upi_pat.sub(lambda m: m.group(1)[:2] + "****@" + m.group(2) if m.group(2).lower() in upi_domains else m.group(0), s)


def obf_email(s: str) -> str:

    return email_pat.sub(lambda m: m.group(0).split("@")[0][:2] + "****@" + m.group(0).split("@")[1], s)


def likely_name(val: str) -> bool:

    if not isinstance(val, str): return False
    tokens = [x for x in re.split(r'\s+', val.strip()) if re.fullmatch(r"[A-Za-z.\-']{2,}", x)]
    return len(tokens) >= 2


def mask_name(txt: str) -> str:

    return " ".join(w[0] + "X"*(len(w)-1) if len(w) > 1 else "X" for w in txt.split()) if isinstance(txt, str) else txt


def valid_ip(x): return isinstance(x, str) and ip_pat.search(x)

def valid_email(x): return isinstance(x, str) and email_pat.search(x)

def valid_upi(x): return isinstance(x, str) and any(m.group(2).lower() in upi_domains for m in upi_pat.finditer(x))

def valid_phone(x): return isinstance(x, str) and ten_digit.search(x)

def valid_aadhar(x): return isinstance(x, str) and (aadhar_pat.search(x) or len(digits_only(x)) == 12)

def valid_passport(x): return isinstance(x, str) and passport_pat.search(x)

def valid_addr(x): return isinstance(x, str) and re.search(r'\d', x) and re.search(r'[A-Za-z]', x) and re.search(r'\b\d{6}\b', x)



def clean_entry(row: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:

    pii_spotted = False
    groups = set()
    clone = dict(row)

    for k, v in row.items():
        key = str(k).lower()
        val = v if isinstance(v, str) else str(v) if v is not None else ""

        if key in keys_map["phone"] and valid_phone(val): pii_spotted = True
        if key in keys_map["aadhar"] and valid_aadhar(val): pii_spotted = True
        if key in keys_map["passport"] and valid_passport(val): pii_spotted = True
        if key in keys_map["upi"] and valid_upi(val): pii_spotted = True
        if key in keys_map["address"] and (valid_phone(val) or valid_aadhar(val) or valid_upi(val)): pii_spotted = True

        if key in keys_map["name"] and likely_name(val): groups.add("name")
        if key in keys_map["fname"] and val: groups.add("fname")
        if key in keys_map["lname"] and val: groups.add("lname")
        if key in keys_map["email"] and valid_email(val): groups.add("email")
        if key in keys_map["address"] and valid_addr(val): groups.add("address")
        if key in keys_map["city"] and val: groups.add("city")
        if key in keys_map["state"] and val: groups.add("state")
        if key in keys_map["pin"] and re.fullmatch(r'\d{6}', str(val)): groups.add("pin")
        if key in keys_map["device"] and val: groups.add("device")
        if key in keys_map["ip"] and valid_ip(val): groups.add("ip")

    if ("city" in groups and "pin" in groups) or ("city" in groups and "state" in groups):
        groups.add("address")

    score = int(("name" in groups or ("fname" in groups and "lname" in groups))) +             int("email" in groups) + int("address" in groups) +             int("device" in groups or "ip" in groups)

    final_flag = pii_spotted or score >= 2

    if final_flag:
        for k, v in clone.items():
            key = str(k).lower()
            val = v if isinstance(v, str) else str(v) if v is not None else ""

            if key in keys_map["phone"] and valid_phone(val): clone[k] = obf_phone(val)
            elif key in keys_map["aadhar"] and valid_aadhar(val): clone[k] = obf_aadhar(val)
            elif key in keys_map["passport"] and valid_passport(val): clone[k] = obf_passport(val)
            elif key in keys_map["upi"] and valid_upi(val): clone[k] = obf_upi(val)
            elif ("name" in groups or ("fname" in groups and "lname" in groups)) and                  (key in keys_map["name"] | keys_map["fname"] | keys_map["lname"]): clone[k] = mask_name(val)
            elif "email" in groups and key in keys_map["email"] and valid_email(val): clone[k] = obf_email(val)
            elif "address" in groups and (key in keys_map["address"] | keys_map["city"] | keys_map["state"] | keys_map["pin"]):
                clone[k] = re.sub(r'\d', 'X', val) if key in keys_map["address"] else val
            elif ("device" in groups or "ip" in groups) and key in keys_map["device"] | keys_map["ip"]:
                clone[k] = "[REDACTED_PII]"
            elif isinstance(v, str) and key in keys_map["address"]:
                clone[k] = obf_phone(obf_upi(obf_aadhar(obf_passport(v))))

    return clone, final_flag


def process_csv(path_in: str, path_out: str):

    out_data: List[Dict[str, Any]] = []
    with open(path_in, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rid = r.get("record_id")
            dataraw = r.get("Data_json") or r.get("data_json") or ""
            data = json_parse(dataraw)
            cleaned, pii = clean_entry(data)
            out_data.append({
                "record_id": rid,
                "redacted_data_json": json.dumps(cleaned, ensure_ascii=False),
                "is_pii": str(pii)
            })
    with open(path_out, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        writer.writerows(out_data)

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 pii_filter_daanushi.py input.csv [output.csv]")
        sys.exit(1)
    in_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else "redacted_output_Daanushi_Sharma.csv"
    process_csv(in_file, out_file)
    print(f"Done: {out_file}")

