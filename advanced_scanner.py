import requests
from PIL import Image
from io import BytesIO
import os
from PIL import Image
from PIL.ExifTags import TAGS

# ---------------- HEADER ANALYSIS ----------------
def check_headers(url):
    print("\n🔐 Header Analysis")

    risk = 0

    try:
        r = requests.get(url, timeout=5)

        headers = r.headers

        important = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for h in important:
            if h in headers:
                print(f"✅ {h} present")
            else:
                print(f"❌ {h} missing")
                risk += 5

    except:
        print("❌ Header Analysis Failed")
        risk += 10

    return risk


# ---------------- DIRECTORY SCAN ----------------
def directory_scan(url):
    print("\n📂 Directory Scan")

    dirs = ["admin", "login", "dashboard", "uploads"]

    for d in dirs:
        target = f"{url}/{d}"

        try:
            r = requests.get(target, timeout=3)

            if r.status_code == 200:
                print(f"⚠️ Found: {target}")

        except:
            pass


# ---------------- XSS SCAN ----------------
def xss_scan(url):
    print("\n🧪 XSS Scan")

    risk = 0
    payload = "<script>alert(1)</script>"

    try:
        r = requests.get(f"{url}?q={payload}", timeout=5)

        if payload in r.text:
            print("⚠️ XSS Possible")
            risk += 25
        else:
            print("✅ XSS Not Detected")

    except:
        print("⚠️ XSS Possible")
        risk += 15

    return risk


# ---------------- SQL INJECTION SCAN ----------------
def sql_scan(url):
    print("\n💉 SQL Injection Scan")

    risk = 0
    payload = "' OR '1'='1"

    try:
        r = requests.get(f"{url}?id={payload}", timeout=5)

        response = r.text.lower()

        confirmed_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "mysql_fetch",
            "sqlstate"
        ]

        possible_errors = [
            "sql",
            "mysql",
            "syntax error",
            "warning",
            "mysqli",
            "pdo",
            "query failed"
        ]

        if any(err in response for err in confirmed_errors):
            print("🚨 SQL Injection Confirmed")
            risk += 40

        elif any(err in response for err in possible_errors):
            print("⚠️ SQL Injection Possible")
            risk += 25

        else:
            print("✅ SQL Injection Not Possible")

    except:
        print("⚠️ SQL Injection Not Detetcted")
        risk += 15

    return risk

# ---------------- IMAGE FILE SCAN ----------------
def scan_image_file(path):

    print("\n🖼 Local Image Scan")

    if not os.path.exists(path):
        print("❌ File not found")
        return

    try:

        img = Image.open(path)

        # ---------------- FILE SIZE ----------------
        size_bytes = os.path.getsize(path)

        if size_bytes < 1024:
            file_size = f"{size_bytes} Bytes"

        elif size_bytes < (1024 * 1024):
            file_size = f"{size_bytes/1024:.2f} KB"

        else:
            file_size = f"{size_bytes/(1024*1024):.2f} MB"

        print(f"📁 File: {path}")
        print(f"📦 File Size: {file_size}")
        print(f"🎨 Format: {img.format}")

        # ---------------- LARGE IMAGE ----------------
        if size_bytes > (5 * 1024 * 1024):
            print("⚠️ Large image file")

        # ---------------- FORMAT CHECK ----------------
        if img.format not in ["PNG", "JPEG", "JPG"]:
            print("⚠️ Uncommon image format")

        print("\n🔎 Hidden Data Analysis")

        metadata_found = False

        # EXIF metadata (JPEG)
        exif = img.getexif()

        if exif:

            metadata_found = True
            print("⚠️ EXIF Metadata Found")

            for tag_id, value in exif.items():

                tag = TAGS.get(tag_id, tag_id)

                if isinstance(value, bytes):
                    value = str(value[:30])

                print(f"- {tag}: {value}")

        # PNG metadata/text chunks
        if img.info:

            metadata_found = True
            print("⚠️ Hidden Metadata Found")

            for key, value in img.info.items():

                print(f"- {key}: {value}")

        if not metadata_found:
            print("✅ No Metadata Found")

        # Hidden comments
        if "comment" in img.info:
            print("⚠️ Hidden Comment Detected")

        # Suspicious raw data scan
        with open(path, "rb") as f:

            raw = f.read()

            suspicious = [
                b"<?php",
                b"<script>",
                b"eval(",
                b"base64",
                b"cmd.exe"
            ]

            found = False

            for s in suspicious:

                if s in raw:

                    print(
                        f"⚠️ Suspicious Hidden Content: "
                        f"{s.decode(errors='ignore')}"
                    )
                    found = True

            if not found:
                print("✅ No Suspicious Hidden Content Found")

        print("\n✅ Image Scan Complete")

    except Exception as e:

        print("Error:", e)
def scan_image_url(url):

    print("\n🌐 Image URL Scan")

    try:

        r = requests.get(url, timeout=5)

        img = Image.open(BytesIO(r.content))

        # ---------- FILE SIZE ----------
        size_bytes = len(r.content)

        if size_bytes < 1024:
            file_size = f"{size_bytes} Bytes"

        elif size_bytes < (1024 * 1024):
            file_size = f"{size_bytes/1024:.2f} KB"

        else:
            file_size = f"{size_bytes/(1024*1024):.2f} MB"

        print(f"🖼 URL: {url}")
        print(f"📦 File Size: {file_size}")
        print(f"🎨 Format: {img.format}")

        # ---------- LARGE IMAGE ----------
        if size_bytes > (5 * 1024 * 1024):
            print("⚠️ Large image file")

        # ---------- FORMAT ----------
        if img.format not in ["PNG", "JPEG", "JPG"]:
            print("⚠️ Uncommon image format")

        print("\n🔎 Hidden Data Analysis")

        metadata_found = False

        # ---------- EXIF ----------
        exif = img.getexif()

        if exif:

            metadata_found = True
            print("⚠️ EXIF Metadata Found")

            for tag_id, value in exif.items():

                tag = TAGS.get(tag_id, tag_id)

                if isinstance(value, bytes):
                    value = str(value[:30])

                print(f"- {tag}: {value}")

        # ---------- IMG.INFO ----------
        if img.info:

            metadata_found = True
            print("⚠️ Hidden Metadata Found")

            for key, value in img.info.items():

                if key == "icc_profile":

                    size = len(value)

                    print(
                        f"- ICC Profile present "
                        f"({size/1024:.2f} KB)"
                    )

                    continue

                value = str(value)

                if len(value) > 100:
                    value = value[:100] + "..."

                print(f"- {key}: {value}")

        if not metadata_found:
            print("✅ No Metadata Found")

        # ---------- COMMENTS ----------
        if "comment" in img.info:
            print("⚠️ Hidden Comment Detected")

        # ---------- SUSPICIOUS STRINGS ----------
        raw = r.content

        suspicious = [
            b"<?php",
            b"<script>",
            b"eval(",
            b"base64",
            b"cmd.exe"
        ]

        found = False

        for s in suspicious:

            if s in raw:

                print(
                    f"⚠️ Suspicious Hidden Content: "
                    f"{s.decode(errors='ignore')}"
                )

                found = True

        if not found:
            print("✅ No Suspicious Hidden Content Found")

        print("\n✅ Image Scan Complete")

    except Exception as e:

        print("Error:", e)
# ---------------- FULL SCAN ----------------
def full_scan(url):
    print("\n🚀 Running Full Scan")

    total_risk = 0

    total_risk += check_headers(url)

    directory_scan(url)

    total_risk += xss_scan(url)

    total_risk += sql_scan(url)

    print(f"\n📊 Security Risk Score: {total_risk}/100")

    if total_risk <= 20:
        print("🟢 Risk Level: LOW")

    elif total_risk <= 50:
        print("🟠 Risk Level: MEDIUM")

    elif total_risk <= 75:
        print("🔴 Risk Level: HIGH")

    else:
        print("🚨 Risk Level: CRITICAL")
        return result
