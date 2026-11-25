import streamlit as st
import pandas as pd
import json
import os
from parser import IOCParser
from normalizer import NormalizationEngine
from correlator import CorrelationEngine
from exporter import BlocklistAndReportExporter

st.set_page_config(page_title="Threat Intelligence Aggregator (Non-AI)", page_icon="🛡️", layout="wide")

st.title("🛡️ Threat Intelligence Aggregator (Non-AI)")
st.markdown("Deterministic IOC Collection, Parsing, Normalization, Cross-Feed Correlation & Automated Blocklist Generation.")

# Load default feeds or uploaded files
parser = IOCParser()
normalizer = NormalizationEngine()
correlator = CorrelationEngine()

st.sidebar.header("1. Ingest Threat Feeds")
uploaded_files = st.sidebar.file_uploader(
    "Upload Custom TI Feeds (CSV, TXT, JSON, STIX)",
    type=["csv", "txt", "json"],
    accept_multiple_files=True
)
use_default = st.sidebar.checkbox("Include Built-in Sample Feeds (OTX, Abuse.ch, CERT, STIX)", value=True)

raw_iocs = []
processed_sources = []

if use_default and os.path.exists("feeds"):
    for fname in sorted(os.listdir("feeds")):
        fpath = os.path.join("feeds", fname)
        if os.path.isfile(fpath):
            raw_iocs.extend(parser.parse_file(fpath))
            processed_sources.append(fname)

if uploaded_files:
    for uf in uploaded_files:
        temp_path = f"temp_{uf.name}"
        with open(temp_path, "wb") as f:
            f.write(uf.getbuffer())
        raw_iocs.extend(parser.parse_file(temp_path))
        processed_sources.append(uf.name)
        os.remove(temp_path)

if raw_iocs:
    normalized = normalizer.normalize(raw_iocs)
    correlated = correlator.correlate(normalized)

    exporter = BlocklistAndReportExporter(output_dir="output")
    exporter.export_normalized_db(normalized)
    exporter.export_correlation_results(correlated)
    exporter.generate_blocklists(correlated)
    report_md = exporter.generate_summary_report(processed_sources, correlated)

    df = pd.DataFrame(correlated)

    # Top KPI Metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Feeds Processed", len(processed_sources))
    c2.metric("Unique Validated IOCs", len(df))
    c3.metric("High Severity (3+ Feeds)", len(df[df["severity"] == "High"]))
    c4.metric("Medium Severity (2 Feeds)", len(df[df["severity"] == "Medium"]))

    tab1, tab2, tab3, tab4 = st.tabs(["📊 Correlated IOCs", "🚫 Deployment Blocklists", "🗂️ Normalized Database", "📄 Executive TI Report"])

    with tab1:
        st.subheader("Cross-Feed Correlation & Severity Scoring")
        sev_filter = st.multiselect("Filter by Severity", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
        filtered_df = df[df["severity"].isin(sev_filter)]
        st.dataframe(filtered_df, use_container_width=True)

    with tab2:
        st.subheader("Deployment-Ready Security Blocklists")
        b1, b2, b3 = st.columns(3)
        with b1:
            st.markdown("**Firewall IP Blocklist (`firewall_ips.txt`)**")
            ip_txt = open("output/blocklists/firewall_ips.txt").read()
            st.code(ip_txt, language="text")
            st.download_button("Download IP Blocklist", ip_txt, "firewall_ips.txt")
        with b2:
            st.markdown("**Web Filter Domains/URLs (`webfilter_domains_urls.txt`)**")
            web_txt = open("output/blocklists/webfilter_domains_urls.txt").read()
            st.code(web_txt, language="text")
            st.download_button("Download Web Filter List", web_txt, "webfilter_domains_urls.txt")
        with b3:
            st.markdown("**EDR/AV Hash Blocklist (`edr_hashes.txt`)**")
            hash_txt = open("output/blocklists/edr_hashes.txt").read()
            st.code(hash_txt, language="text")
            st.download_button("Download Hash Blocklist", hash_txt, "edr_hashes.txt")

    with tab3:
        st.subheader("Unified Normalized IOC Schema")
        st.json(normalized)

    with tab4:
        st.markdown(report_md)
        st.download_button("Download TI Summary Report (.md)", report_md, "ti_summary_report.md")
else:
    st.warning("No threat feeds loaded. Enable sample feeds or upload CSV/TXT/JSON/STIX files in the sidebar.")
