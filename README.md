# PhishSight

A powerful, terminal-based phishing page analyzer and decoy generator, designed for cybersecurity professionals and penetration testers. Run it directly on your Kali Linux machine without any API dependencies.

![PhishSight Banner](https://i.imgur.com/your-banner-image.png) *(Yahan apni koi screenshot ya banner daal sakte ho)*

## Features

- **Offline Analysis:** Analyze suspicious URLs without sending data to any third-party service.
- **Smart Detection:** Detects typosquatting, suspicious TLDs, and malicious form actions.
- **Brand Targeting:** Identifies which brand (e.g., Google, Facebook, Instagram) the phishing page is imitating.
- **Decoy Generator:** Creates a harmless, visual clone of the phishing page for safe demonstration and training purposes.
- **Colorful CLI:** A beautiful and easy-to-read command-line interface.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/phishsight.git
    ```
2.  Navigate into the tool's directory:
    ```bash
    cd phishsight
    ```
3.  Install the required Python libraries:
    ```bash
    pip3 install -r requirements.txt
    ```

## Usage

### Basic Analysis

To analyze a suspicious URL, use the `-u` or `--url` flag:

```bash
python3 phishsight.py -u "http://suspicious-site.com/login"
