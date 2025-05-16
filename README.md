# SecureComm: Secure Communication System with Dynamic Keys and ML-based Intrusion Detection

## 🎯 General Objective

Develop a real-time encrypted peer-to-peer communication system that:

* Generates dynamic keys for each session based on ECDH (Elliptic Curve Diffie-Hellman) exchange.
* Uses Python to implement both the communication protocol and cryptography.
* Includes an intrusion/anomaly detection layer with Machine Learning, identifying suspicious patterns such as man-in-the-middle or replay attacks.

## 🧠 Technologies and Concepts

* **Python:** `sockets` for communication, `cryptography` for cryptographic operations, `scikit-learn` and `pandas` for Machine Learning.
* **Cryptography:**
    * Key Exchange: Elliptic Curve Diffie-Hellman (ECDH) with SECP384R1 curve.
    * Session Encryption: AES-GCM with 256-bit keys derived via HKDF (SHA256) from the ECDH secret.
    * Forward Secrecy: Ephemeral ECDH keys generated for each session.
    * Message Integrity and Authenticity: Digital signatures using ECDSA with SECP384R1 curve and SHA256 hash.
* **Communication:** P2P protocol over TCP/IP, with messages serialized in JSON.
* **Anomaly Detection:** Scikit-learn's `IsolationForest` model to detect anomalous patterns in communication traffic. Initial features include message size, interval between messages, and message count in a time window.
* **Logging:** Logging of important events with file rotation, using Python's `logging` module.

## 📂 Project Structure

```
/securecomm/
├── core/                     # Core application modules
│   ├── crypto.py             # ECDH + AES-GCM implementation
│   ├── auth.py               # Digital Signature implementation (ECDSA)
│   ├── comm.py               # Secure P2P socket communication logic
│   └── anomaly.py            # ML model for anomaly detection and its functions
├── server/                   # Server-specific logic (if needed, currently integrated in comm.py and client.py)
│   ├── server.py             # (Planned, but functionality may be in client.py/comm.py for pure P2P)
│   └── session_manager.py    # (Planned, session management integrated in comm.py)
├── client/                   # Client-specific logic
│   └── client.py             # CLI client implementation (TO BE DEVELOPED)
├── data/                     # Data for training and ML models
│   ├── training_data.csv     # (Planned for generated training data)
│   └── anomaly_detector_model.joblib # Trained anomaly detection model
│   └── anomaly_scaler.joblib   # Scaler for model data
├── utils/                    # Utilities
│   └── logger.py             # Logging module
├── logs/                     # Directory for log files
│   └── secure_comm.log       # Main log file
├── venv/                     # Python virtual environment
└── README.md                 # This file
```

## ⚙️ Setup and Installation

1. **Clone the repository (if applicable) or manually create the directory structure.**

2. **Create and activate a Python virtual environment:**
   ```bash
   cd securecomm
   python3.11 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install cryptography scikit-learn pandas joblib
   ```

## 🚀 How to Execute

Currently, the modules `core/crypto.py`, `core/auth.py`, `core/comm.py`, and `core/anomaly.py` contain `if __name__ == '__main__':` sections with usage examples and basic tests. To run these individual tests:

```bash
python -m core.crypto
python -m core.auth
python -m core.comm # This will attempt basic P2P communication with anomaly detection
python -m core.anomaly # This will test training/loading the anomaly model
python -m utils.logger # This will test the logger
```

A complete client-server application (`client/client.py` and `server/server.py` or a unified executable peer script) still needs to be developed to demonstrate the system interactively.

### Running the Communication Test (`core/comm.py`)

When executed directly (`python -m core.comm`), `core/comm.py` will attempt to:
1. Start a "Peer 1" (server) on `localhost:12345`.
2. Start a "Peer 2" (client) that will connect to Peer 1.
3. Perform a cryptographic handshake.
4. Exchange some test messages.
5. Use the `AnomalyDetector` (loading a model from `data/anomaly_detector_model.joblib` or training a dummy one if it doesn't exist) to verify the messages.

Make sure the `data/` directory exists within `securecomm/` so that the anomaly model can be saved/loaded.

## 🧠 Machine Learning Model Training (Anomaly Detection)

The `core/anomaly.py` module implements the `AnomalyDetector` class which uses `IsolationForest`.

1. **Data Generation:**
   * Currently, `core/anomaly.py` includes a generation of *dummy data* for testing purposes within its `if __name__ == '__main__':` block.
   * For real training, a separate script (e.g., `data/training_data_generator.py`) would be needed to simulate normal and attack traffic, extracting features such as:
     * `message_length`: Message size.
     * `time_interval`: Time since the last message from the same peer.
     * `message_count_window`: Number of messages from the peer in a time window (e.g., last 60s).
     * Other relevant features (e.g., message type, decryption/signature failures).
   * This script would generate a `training_data.csv` in the `data/` directory.

2. **Model Training:**
   * After generating `training_data.csv`, the model can be trained by executing a training function that uses `AnomalyDetector.train(dataframe)`.
   * The `AnomalyDetector` will save the trained model as `data/anomaly_detector_model.joblib` and the scaler as `data/anomaly_scaler.joblib`.
   * The `core/comm.py` will try to load this saved model. If it doesn't find it, the `AnomalyDetector` inside `comm.py` (in its `__main__` test) will train a dummy model to allow running the communication tests.

## 📝 Expected Results

* **High security:** Even if a session key is discovered, the content of past sessions is not compromised (Forward Secrecy).
* **Ability to detect and alert about unusual usage patterns** (e.g., MITM attempts, anomalous traffic) through the Machine Learning module.
* **Application with potential** to be used in corporate environments or decentralized messengers.

## 🛣️ Next Steps (Development)

* Complete development of `client/client.py` with CLI interface.
* Development of a robust `server/server.py` or a unified executable peer script.
* Creation of a dedicated script for training data generation (`data/training_data_generator.py`).
* Implementation of a more explicit alert mechanism in the client for detected anomalies.
* Complete integration tests and performance benchmarking.
* Refinements and optimizations.
* (Optional) Implementation of encrypted logging (currently uses standard file logging).
* (Optional) WebSocket interface and public key exchange with QR code.

