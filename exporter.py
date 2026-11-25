import os
import json
import csv
from datetime import datetime, timezone

class BlocklistAndReportExporter:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        self.blocklist_dir = os.path.join(output_dir, "blocklists")
        os.makedirs(self.blocklist_dir, exist_ok=True)

    def export_normalized_db(self, normalized_records: list):
        with open(os.path.join(self.output_dir, "normalized_iocs.json"), "w", encoding="utf-8") as f:
            json.dump(normalized_records, f, indent=2)

    def export_correlation_results(self, correlated_records: list):
        with open(os.path.join(self.output_dir, "correlation_report.json"), "w", encoding="utf-8") as f:
            json.dump(correlated_records, f, indent=2)

        with open(os.path.join(self.output_dir, "correlation_report.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Indicator", "Type", "Severity", "Feed_Count", "Sources", "Categories"])
            for item in correlated_records:
                writer.writerow([
                    item["indicator"], item["type"], item["severity"],
                    item["feed_count"], "; ".join(item["sources"]), "; ".join(item["categories"])
                ])

    def generate_blocklists(self, correlated_records: list):
        firewall_ips = [r["indicator"] for r in correlated_records if r["type"] == "ip"]
        web_filters = [r["indicator"] for r in correlated_records if r["type"] in ("domain", "url")]
        edr_hashes = [r["indicator"] for r in correlated_records if r["type"] == "hash"]

        with open(os.path.join(self.blocklist_dir, "firewall_ips.txt"), "w", encoding="utf-8") as f:
            f.write("# Automated Firewall IP Blocklist\n" + "\n".join(firewall_ips) + "\n")

        with open(os.path.join(self.blocklist_dir, "webfilter_domains_urls.txt"), "w", encoding="utf-8") as f:
            f.write("# Automated Web Filter Domain & URL Blocklist\n" + "\n".join(web_filters) + "\n")

        with open(os.path.join(self.blocklist_dir, "edr_hashes.txt"), "w", encoding="utf-8") as f:
            f.write("# Automated EDR/AV Malicious Hash Blocklist\n" + "\n".join(edr_hashes) + "\n")

        with open(os.path.join(self.blocklist_dir, "unified_blocklist.json"), "w", encoding="utf-8") as f:
            json.dump({
                "firewall_ip_set": firewall_ips,
                "web_filter_urls_domains": web_filters,
                "edr_av_hashes": edr_hashes
            }, f, indent=2)

    def generate_summary_report(self, feed_files: list, correlated_records: list) -> str:
        high_sev = [r for r in correlated_records if r["severity"] == "High"]
        med_sev = [r for r in correlated_records if r["severity"] == "Medium"]
        low_sev = [r for r in correlated_records if r["severity"] == "Low"]

        type_counts = {}
        for r in correlated_records:
            type_counts[r["type"]] = type_counts.get(r["type"], 0) + 1

        report_lines = [
            "# Threat Intelligence Aggregation & Correlation Report",
            f"**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## 1. Feed Processing Summary",
            f"- **Total Feeds Processed:** {len(feed_files)}",
            f"- **Feed Sources:** {', '.join(feed_files)}",
            f"- **Total Unique Validated IOCs:** {len(correlated_records)}",
            "",
            "## 2. Indicator Breakdown by Type",
        ]
        for k, v in sorted(type_counts.items()):
            report_lines.append(f"- **{k.upper()}:** {v}")

        report_lines.extend([
            "",
            "## 3. Severity Distribution",
            f"- **High Severity (3+ feeds):** {len(high_sev)}",
            f"- **Medium Severity (2 feeds):** {len(med_sev)}",
            f"- **Low Severity (1 feed):** {len(low_sev)}",
            "",
            "## 4. High & Medium Priority Repeated Indicators",
            "| Indicator | Type | Severity | Feed Count | Sources |",
            "| :--- | :--- | :--- | :---: | :--- |"
        ])
        for r in high_sev + med_sev:
            report_lines.append(
                f"| `{r['indicator']}` | {r['type'].upper()} | **{r['severity']}** | {r['feed_count']} | {', '.join(r['sources'])} |"
            )

        report_text = "\n".join(report_lines)
        with open(os.path.join(self.output_dir, "ti_summary_report.md"), "w", encoding="utf-8") as f:
            f.write(report_text)
        return report_text
