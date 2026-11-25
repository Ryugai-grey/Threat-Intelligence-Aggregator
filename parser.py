import re
import json
import csv
import ipaddress
import os

class IOCParser:
    REGEX_PATTERNS = {
        "url": re.compile(r"https?://[^\s'\"<>\]\)]+", re.IGNORECASE),
        "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|ru|cn|xyz|top|info|biz)\b", re.IGNORECASE),
    }

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (ip_obj.is_private or ip_obj.is_loopback)
        except ValueError:
            return False

    @staticmethod
    def validate_hash(hash_str: str, hash_type: str) -> bool:
        expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        if len(hash_str) != expected_lengths.get(hash_type, 0):
            return False
        try:
            int(hash_str, 16)
            return True
        except ValueError:
            return False

    def extract_from_text(self, raw_text: str, source_name: str, category: str = "Uncategorized") -> list:
        extracted = []
        seen_in_source = set()

        for u in self.REGEX_PATTERNS["url"].findall(raw_text):
            clean_u = u.rstrip(".,;:")
            if ("url", clean_u.lower()) not in seen_in_source:
                seen_in_source.add(("url", clean_u.lower()))
                extracted.append({"raw_value": clean_u, "type": "url", "source": source_name, "category": category})

        for em in self.REGEX_PATTERNS["email"].findall(raw_text):
            if ("email", em.lower()) not in seen_in_source:
                seen_in_source.add(("email", em.lower()))
                extracted.append({"raw_value": em.lower(), "type": "email", "source": source_name, "category": category})

        for ip in self.REGEX_PATTERNS["ipv4"].findall(raw_text):
            if self.validate_ip(ip) and ("ip", ip) not in seen_in_source:
                seen_in_source.add(("ip", ip))
                extracted.append({"raw_value": ip, "type": "ip", "source": source_name, "category": category})

        for h_type in ["sha256", "sha1", "md5"]:
            for h_val in self.REGEX_PATTERNS[h_type].findall(raw_text):
                h_lower = h_val.lower()
                if self.validate_hash(h_lower, h_type) and ("hash", h_lower) not in seen_in_source:
                    seen_in_source.add(("hash", h_lower))
                    extracted.append({
                        "raw_value": h_lower,
                        "type": "hash",
                        "hash_algo": h_type.upper(),
                        "source": source_name,
                        "category": category
                    })

        text_cleaned = self.REGEX_PATTERNS["url"].sub(" ", raw_text)
        text_cleaned = self.REGEX_PATTERNS["email"].sub(" ", text_cleaned)
        for dom in self.REGEX_PATTERNS["domain"].findall(text_cleaned):
            d_lower = dom.lower()
            if ("domain", d_lower) not in seen_in_source:
                seen_in_source.add(("domain", d_lower))
                extracted.append({"raw_value": d_lower, "type": "domain", "source": source_name, "category": category})

        return extracted

    def parse_file(self, filepath: str) -> list:
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        results = []

        with open(filepath, "r", encoding="utf-8") as f:
            if ext == ".csv":
                reader = csv.DictReader(f)
                for row in reader:
                    row_text = " ".join(str(v) for v in row.values())
                    cat = row.get("category", row.get("threat", "CSV Feed Indicator"))
                    results.extend(self.extract_from_text(row_text, filename, cat))
            elif ext == ".json":
                data = json.load(f)
                if isinstance(data, dict) and data.get("type") == "bundle" and "objects" in data:
                    for obj in data["objects"]:
                        if obj.get("type") == "indicator":
                            pattern = obj.get("pattern", "")
                            cat = obj.get("name", "STIX Indicator")
                            results.extend(self.extract_from_text(pattern, f"{filename} (STIX)", cat))
                else:
                    results.extend(self.extract_from_text(json.dumps(data), filename, "JSON Threat Feed"))
            else:
                results.extend(self.extract_from_text(f.read(), filename, "Text Advisory"))

        return results
