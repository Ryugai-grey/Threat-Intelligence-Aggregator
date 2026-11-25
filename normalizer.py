from datetime import datetime, timezone

class NormalizationEngine:
    def __init__(self):
        self.run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def normalize(self, raw_indicators: list) -> list:
        normalized_records = []
        for item in raw_indicators:
            val = item["raw_value"].strip()
            ioc_type = item["type"].lower()
            val = val.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")

            if ioc_type in ("ip", "domain", "hash", "email"):
                val = val.lower()

            normalized_records.append({
                "indicator": val,
                "type": ioc_type,
                "subtype": item.get("hash_algo", ioc_type.upper()),
                "source": item["source"],
                "category": item.get("category", "General Threat"),
                "normalized_at": self.run_timestamp
            })
        return normalized_records
