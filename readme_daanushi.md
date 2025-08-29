PII Redaction Script by Daanushi Sharma

Why I made this-

I wanted a simple way to clean up CSV files that contain sensitive details. Most CSVs have user info inside a JSON column, so I wrote a Python script that finds private data and hides it. The goal was to make sure things like emails, phone numbers or Aadhaar don’t end up exposed when the file is shared.

What it does-

Reads JSON data from a column named Data_json or data_json.

Checks each field to see if it looks like PII (phone, Aadhaar, email, UPI, IP, name etc).

Marks if a row has PII or not.

Masks the values so only partial info is visible (example: emails get **** in the middle, names get part hidden, phone numbers are X’d out).

Finally, writes a new CSV with three columns:

record_id

redacted_data_json

is_pii

How I built it-

Used regex for Aadhaar, passport, emails, IPv4, and 10-digit phones.

Added domain check for UPI so random text doesn’t get flagged.

Wrote small helper functions for masking (email, phone, name etc).

Also checked for combinations like (name + email + address) because sometimes one value alone isn’t enough to call it PII.

Kept the code more spread out so it’s easy to follow.

Running it-

In terminal:

python detector_Daanushi_Sharma.py input.csv output.csv


If output file isn’t given, it saves as:

redacted_output_Daanushi_Sharma.csv

Example output
record_id	redacted_data_json	is_pii
001	{"name": "DaXXXXX ShaXXXX", ...}	True
002	{"email": "ab****@gmail.com"}	True

Features I added-

Works even if the JSON in the CSV is messy

Detects different key names (phone, mobile, alt_phone etc)

Simple redaction style (XXXXX or [REDACTED_PII])

Easy to extend — I can add more patterns later


