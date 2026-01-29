# CerberusEye

**Research Infrastructure for the Sigmund Protocol**

[🌐 **Official Website**](http://professorsigmund.com/) | [📄 **Read the White Paper**](glass_box_paradox.pdf)

### Overview
CerberusEye is a localized infrastructure auditing tool designed to quantify the exposure of self-hosted LLM inference endpoints. It serves as the data collection methodology for the research paper *"The Glass Box Paradox."*

### Deployment & Usage

**1. Bring Your Own Key (BYOK)**
This tool distributes **no API keys**. To utilize the OSINT features (Shodan, Censys, LeakIX), you must enter your own credentials in the dashboard. These keys are stored locally on your machine in `config.ini` and are never transmitted to XORD.

**2. Automatic Launch**
The server on port 5000 starts automatically. You only need to click **INITIATE SCAN** in the interface to begin operations.

**3. Offline / Free Mode**
API keys are **not required** to use the tool. You can use the "Manual IP List" feature to scan specific targets without any third-party services. The tool's deep scanning and vulnerability detection logic functions 100% offline.

### Research Data
**[Download the full PDF Report](glass_box_paradox.pdf)**
