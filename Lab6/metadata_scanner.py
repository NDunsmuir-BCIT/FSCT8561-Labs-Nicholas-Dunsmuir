from pathlib import Path
from PIL import Image, ExifTags
import csv
import base64
import re

image_dir = Path(__file__).parent / "Images"
results = []

for image_path in sorted(image_dir.glob("*.png")):
    with Image.open(image_path) as img:
        found = []

        exif = img.getexif()
        for tag_id, value in exif.items():
            found.append(("EXIF", ExifTags.TAGS.get(tag_id, tag_id), value))
        for tag_id, value in exif.get_ifd(0x8769).items():
            found.append(("EXIF", ExifTags.TAGS.get(tag_id, tag_id), value))
        has_gps = len(exif.get_ifd(0x8825)) > 0

        for key, value in img.info.items():
            if isinstance(value, str) and key not in ("XML:com.adobe.xmp", "xmp"):
                found.append(("PNG text", key, value))

        xmp = img.info.get("XML:com.adobe.xmp") or img.info.get("xmp")
        if isinstance(xmp, bytes):
            xmp = xmp.decode("utf-8", errors="replace")
        if xmp:
            for tag, text in re.findall(r"<([\w:]+)>([^<]+)</\1>", xmp):
                found.append(("XMP", tag, text))

        result = {
            "filename": image_path.name,
            "format": img.format,
            "metadata_fields": ", ".join(img.info.keys()),
            "suspected_field": "",
            "encoding": "",
            "risk_score": 0,
            "reason": "",
        }

        suspects, encodings, reasons = [], [], []
        covert = encoded = False

        for meta_type, field, value in found:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace").replace("ASCII", "").strip("\x00 ")
            value = str(value).strip()

            text, enc = value, "plain text"
            if re.fullmatch(r"[A-Za-z0-9+/]{16,}={0,2}", value):
                try:
                    text = base64.b64decode(value).decode("utf-8")
                    enc = "Base64"
                    encoded = True
                except Exception:
                    pass

            if re.match(r"[A-Z]{3,}: ", text):
                covert = True
                suspects.append(f"{meta_type} {field}")
                encodings.append(enc)

        if covert:
            result["risk_score"] += 10
            reasons.append("+10 covert message in " + ", ".join(suspects))
        if encoded:
            result["risk_score"] += 5
            reasons.append("+5 Base64-encoded value")
        if has_gps:
            result["risk_score"] += 5
            reasons.append("+5 embedded GPS coordinates")
        elif len(suspects) > 1:
            result["risk_score"] += 5
            reasons.append("+5 same value stored in multiple metadata types")

        result["suspected_field"] = "; ".join(suspects) or "none"
        result["encoding"] = "; ".join(sorted(set(encodings))) or "n/a"
        result["reason"] = "; ".join(reasons) or "no indicators found"
        results.append(result)

report_path = Path(__file__).parent / "metadata_report.csv"
with open(report_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("Saved", len(results), "rows to", report_path, "\n")
for r in results:
    print(r["filename"], "| score:", r["risk_score"], "|", r["suspected_field"], "|", r["encoding"], "|", r["reason"])