# 🛡️ Web-Based Analysis Intrusion Detection System

This project implements a Python-based Intrusion Detection System (IDS) designed to analyze network traffic and detect potential threats, such as SYN flood attacks. It utilizes predefined rules and real-time packet analysis to identify malicious activities.

## 🚀 Features

- **SYN Flood Detection**: Identifies SYN flood attacks by monitoring TCP handshake anomalies.
- **Rule-Based Analysis**: Applies custom rules defined in `rules.csv` for detecting various intrusion patterns.
- **Packet Unpacking**: Processes and unpacks network packets for detailed inspection.
- **Alert Mechanism**: Triggers audible alerts (`warning_sound.mp3`) upon detecting suspicious activities.

## 🛠️ Technologies Used

- Python
- Scapy (for packet manipulation)
- CSV (for rule definitions)
- Audio playback libraries (for alerts)

## 📁 Project Structure

```
web-bases-analysis-intrusion-detection-system/
├── __pycache__/                 # Compiled Python files
├── main.py                      # Main script to run the IDS
├── rules.csv                    # CSV file containing detection rules
├── rules.py                     # Module to parse and apply rules
├── syn_flood_attack_detection.py# Module for detecting SYN flood attacks
├── unpack.py                    # Module for unpacking network packets
└── warning_sound.mp3            # Audio file for alert notifications
```

## ⚙️ Setup Instructions

### Prerequisites

- Python 3.x installed on your system.
- Necessary Python libraries:
  ```bash
  pip install scapy playsound
  ```

### Running the IDS

1. Clone the repository:
   ```bash
   git clone https://github.com/ojasshukla01/web-bases-analysis-intrusion-detection-system.git
   cd web-bases-analysis-intrusion-detection-system
   ```

2. Execute the main script:
   ```bash
   python main.py
   ```

The system will start monitoring network traffic and will alert upon detecting any suspicious activity based on the defined rules.

## 📄 Rule Definition (`rules.csv`)

The `rules.csv` file contains the criteria for identifying potential threats. Each rule should be defined with appropriate parameters that the system can parse and apply during packet analysis.

## 🔊 Alert Mechanism

Upon detecting an intrusion, the system plays the `warning_sound.mp3` file to notify the user of potential threats.

## 👨‍💻 Author

**Ojas Shukla**  
Data Engineer | Cloud-Native Enthusiast 
[LinkedIn](https://linkedin.com/in/ojasshukla01) · [GitHub](https://github.com/ojasshukla01)
