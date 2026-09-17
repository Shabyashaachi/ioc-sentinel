# Architecture

```text
                +------------------+
                | CSV Security Logs |
                +--------+---------+
                         |
                         v
                 +---------------+
                 | Event Parser  |
                 +-------+-------+
                         |
                         v
                +----------------+
                | IOC Extraction |
                +-------+--------+
                        |
             +----------+----------+
             |                     |
             v                     v
       +-----------+       +---------------+
       | IOC Feed  |       | Behavior Rules|
       +-----+-----+       +-------+-------+
             |                     |
             +----------+----------+
                        v
                 +--------------+
                 | Risk Scoring |
                 +------+-------+
                        v
               +------------------+
               | JSON / CSV / CLI |
               +------------------+
```

The design is intentionally modular so future adapters can feed Wazuh, Splunk, MISP/OpenCTI or API data into the same detection and scoring pipeline.
