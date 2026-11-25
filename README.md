# Threat Intelligence Aggregator (Non-AI)

A deterministic, rule-based Threat Intelligence (TI) Aggregation toolkit built in Python to collect, parse, validate, normalize, correlate, and export Indicators of Compromise (IOCs) across heterogeneous security feeds—without relying on AI or machine learning.

## Features
- **Multi-Format Parser (`parser.py`)**: Extracts and validates IPv4 addresses, domains, URLs, file hashes (MD5/SHA1/SHA256), and email indicators from **CSV, TXT, JSON, and STIX 2.x** feeds.
- **Normalization Engine (`normalizer.py`)**: Standardizes indicators into a unified JSON schema with source, category, and UTC timestamp metadata.
- **Cross-Feed Correlation Engine (`correlator.py`)**: Detects repeated malicious infrastructure across multiple sources and assigns **Low / Medium / High** severity scores.
- **Automated Blocklist & Report Generator (`exporter.py`)**: Exports deployment-ready blocklists for Firewalls, Web Filters, and EDR/AV tools alongside a Markdown/CSV intelligence report.
- **Interactive Web Dashboard (`app.py`)**: Streamlit web interface for live feed ingestion, correlation filtering, and one-click blocklist downloads.

## Quick Start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the CLI Pipeline:
   ```bash
   python main.py
   ```
3. Launch the Interactive Web App:
   ```bash
   streamlit run app.py
   ```
