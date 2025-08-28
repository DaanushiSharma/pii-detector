# PII Redaction Script — Written by Daanushi Sharma

## Overview

This Python script is something I built to automatically detect and redact Personally Identifiable Information (PII) from CSV data. Each row in the input CSV contains a JSON field, and the script returns a new CSV with masked or redacted PII.

This can be used in situations where sensitive user data needs to be hidden for privacy or compliance reasons.


##  What It Does

For each record in the CSV, the script:

1. Parses the JSON safely from a column named `Data_json` or `data_json`.
2. Identifies fields that may contain PII using regular expressions and key name patterns.
3. Flags whether a row contains PII.
4. Applies masking/redaction to phone numbers, Aadhaar, email, names, UPI, IP, etc.
5. Outputs a new CSV with the following columns:
   - record_id
   - redacted_data_json
   - is_pii


## How I Wrote It

- I used regex patterns for Aadhaar numbers, emails, passports, IPv4 addresses, and 10-digit mobile numbers.
- I added domain-level filtering for UPI IDs to avoid false positives.
- I created helper functions like `obf_email`, `obf_phone`, `mask_name`, etc. for redaction.
- The detection logic also checks combinations of values (like name + email + address) to determine PII risk even when individual fields aren't enough alone.
- I avoided reducing the code into fewer lines so that everything stays clear and readable.

---

##  How to Run

Open your terminal or command prompt and run:

```bash
python detector_Daanushi_Sharma.py input.csv output.csv
```

If you don't pass the output file, it defaults to:

```
redacted_output_Daanushi_Sharma.csv
```



## Output Format

| record_id | redacted_data_json               | is_pii |
|-----------|----------------------------------|--------|
| 001       | {"name": "DaXXXXX ShaXXXX", ...} | True   |
| 002       | {"email": "ab****@gmail.com"}    | True   |



## Features

- Handles both clean JSON and broken stringified dicts
- Flexible key detection (like phone, mobile, alt_phone, etc.)
- Masking is done with character substitution and fixed tokens (like XXXXXX or [REDACTED_PII])
- Easy to extend and more PII types can be added

