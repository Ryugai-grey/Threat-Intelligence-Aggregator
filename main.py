import os
from parser import IOCParser
from normalizer import NormalizationEngine
from correlator import CorrelationEngine
from exporter import BlocklistAndReportExporter

def main():
    print("=" * 65)
    print("   THREAT INTELLIGENCE AGGREGATOR (NON-AI) - EXECUTION LOG")
    print("=" * 65)

    feeds_dir = "feeds"
    feed_files = [
        os.path.join(feeds_dir, f)
        for f in sorted(os.listdir(feeds_dir))
        if os.path.isfile(os.path.join(feeds_dir, f))
    ]
    print(f"\n[STEP 1] Loaded {len(feed_files)} feeds: {[os.path.basename(f) for f in feed_files]}")

    parser = IOCParser()
    raw_iocs = []
    print("\n[STEP 2] Parsing & Validating IOCs...")
    for fpath in feed_files:
        parsed = parser.parse_file(fpath)
        print(f" -> {os.path.basename(fpath)}: {len(parsed)} valid IOCs extracted")
        raw_iocs.extend(parsed)

    print("\n[STEP 3] Normalizing Indicators...")
    normalizer = NormalizationEngine()
    normalized_iocs = normalizer.normalize(raw_iocs)
    print(f" -> Normalized {len(normalized_iocs)} total records.")

    print("\n[STEP 4] Running Cross-Feed Correlation Engine...")
    correlator = CorrelationEngine()
    correlated_iocs = correlator.correlate(normalized_iocs)
    repeated = [c for c in correlated_iocs if c["feed_count"] > 1]
    print(f" -> Unique IOCs: {len(correlated_iocs)} | Repeated Across Feeds: {len(repeated)}")
    for item in repeated:
        print(f"    * [{item['severity'].upper()}] {item['indicator']} ({item['type']}) -> {item['feed_count']} feeds")

    print("\n[STEP 5 & 6] Generating Blocklists & Final Intelligence Report...")
    exporter = BlocklistAndReportExporter(output_dir="output")
    exporter.export_normalized_db(normalized_iocs)
    exporter.export_correlation_results(correlated_iocs)
    exporter.generate_blocklists(correlated_iocs)
    exporter.generate_summary_report([os.path.basename(f) for f in feed_files], correlated_iocs)
    print(" -> All outputs saved to ./output/")

if __name__ == "__main__":
    main()
