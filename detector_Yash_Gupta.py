import csv
import json
import re
import sys

def mask_name(full_name):
    parts = full_name.split()
    masked_parts = []
    for p in parts:
        if len(p) > 1:
            masked_parts.append(p[0] + "*" * (len(p)-1))
        else:
            masked_parts.append(p)
    return " ".join(masked_parts)

def redact_pii(data):
    is_pii = False
    redacted = {}

    for key, value in data.items():
        if not value:
            redacted[key] = value
            continue

        # Phone number
        if key == "phone" or key == "contact":
            if re.fullmatch(r"\d{10}", str(value)):
                redacted[key] = value[:2] + "XXXXXX" + value[-2:]
                is_pii = True
                continue

        # Aadhaar
        if key == "aadhar":
            if re.fullmatch(r"\d{12}", str(value)):
                redacted[key] = value[:4] + "XXXXXXXX" + value[-4:]
                is_pii = True
                continue

        # Passport
        if key == "passport":
            if re.fullmatch(r"[A-Z][0-9]{7}", str(value)):
                redacted[key] = value[0] + "XXXXXXX"
                is_pii = True
                continue

        # UPI ID
        if key == "upi_id":
            if "@" in str(value):
                prefix, domain = value.split("@", 1)
                redacted[key] = prefix[:2] + "XXXX@" + domain
                is_pii = True
                continue

        # Name
        if key == "name":
            redacted[key] = mask_name(str(value))
            is_pii = True
            continue

        # Email
        if key == "email":
            if "@" in str(value):
                local, domain = value.split("@", 1)
                redacted[key] = local[:2] + "XXX@" + domain
                is_pii = True
                continue

        # Address
        if key == "address":
            redacted[key] = "[REDACTED_ADDRESS]"
            is_pii = True
            continue

        # IP / Device ID (with context)
        if key in ["ip_address", "device_id"]:
            redacted[key] = "[REDACTED_" + key.upper() + "]"
            is_pii = True
            continue

        # Otherwise keep as is
        redacted[key] = value

    return redacted, is_pii


def main(input_file):
    output_file = "redacted_output_candidate_full_name.csv"

    with open(input_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            try:
                data = json.loads(row["Data_json"].replace("'", "\""))
            except Exception:
                writer.writerow({
                    "record_id": row["record_id"],
                    "redacted_data_json": "{}",
                    "is_pii": False
                })
                continue

            redacted, is_pii = redact_pii(data)

            writer.writerow({
                "record_id": row["record_id"],
                "redacted_data_json": json.dumps(redacted),
                "is_pii": is_pii
            })

    print(f"✅ Done! Output written to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    main(sys.argv[1])
