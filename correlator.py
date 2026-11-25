from collections import defaultdict

class CorrelationEngine:
    @staticmethod
    def assign_severity(feed_count: int) -> str:
        if feed_count >= 3:
            return "High"
        elif feed_count == 2:
            return "Medium"
        return "Low"

    def correlate(self, normalized_records: list) -> list:
        grouped = defaultdict(lambda: {
            "type": "",
            "subtype": "",
            "sources": set(),
            "categories": set(),
            "total_occurrences": 0
        })

        for rec in normalized_records:
            ind = rec["indicator"]
            grouped[ind]["type"] = rec["type"]
            grouped[ind]["subtype"] = rec["subtype"]
            grouped[ind]["sources"].add(rec["source"])
            grouped[ind]["categories"].add(rec["category"])
            grouped[ind]["total_occurrences"] += 1

        correlated_list = []
        for indicator, meta in grouped.items():
            feed_count = len(meta["sources"])
            correlated_list.append({
                "indicator": indicator,
                "type": meta["type"],
                "subtype": meta["subtype"],
                "feed_count": feed_count,
                "total_occurrences": meta["total_occurrences"],
                "sources": sorted(list(meta["sources"])),
                "categories": sorted(list(meta["categories"])),
                "severity": self.assign_severity(feed_count)
            })

        correlated_list.sort(key=lambda x: (-x["feed_count"], x["indicator"]))
        return correlated_list
