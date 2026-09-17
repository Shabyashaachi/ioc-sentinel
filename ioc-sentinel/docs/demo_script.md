# 60-second portfolio demo

1. Run `python -m ioc_sentinel demo`.
2. Show the brute-force sequence and malicious-IP match.
3. Run `python -m ioc_sentinel scan samples/security_events.csv --ioc-feed samples/iocs.csv --format json --output reports.json`.
4. Open `reports.json` and explain the score, reasons, and evidence fields.
5. Explain that the detector uses transparent rules and is ready for Wazuh/Splunk/MISP adapters.
