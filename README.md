# 🚨 AI_IDS – AI-powered Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey)]()
[![ML Model](https://img.shields.io/badge/Model-Scikit--Learn-orange)](https://scikit-learn.org/)
[![GUI](https://img.shields.io/badge/GUI-Tkinter-yellow)]()

> 🛡 **AI-powered Intrusion Detection System** using **Machine Learning** and a **Tkinter GUI** for real-time network threat detection.

---

## 📌 Features
✅ **Machine Learning-based Detection** – Trained on the **KDD Cup 99 dataset**  
✅ **User-Friendly Tkinter GUI** – Simple & clean interface  
✅ **Full 41-Feature Support** – Matches the trained model’s input requirements  
✅ **Real-Time Threat Classification** – Instant results for each entry  
✅ **Vertical Scrolling** – Smooth navigation in the app  
✅ **Pre-trained Encoders** – Handles categorical features (`protocol_type`, `service`, `flag`)  

---


## 📂 Project Structure
AI_IDS/
│
├── encoders/ # Label encoders for categorical features
├── models/ # Trained ML models
├── .gitignore
├── KDDTest+.txt # Test dataset
├── KDDTrain+.txt # Training dataset
├── LICENSE # MIT License
├── README.md # Documentation
├── gui_app.py # Tkinter GUI application
├── le_flag.joblib # Label encoder for "flag"
├── le_service.joblib # Label encoder for "service"
└── le_protocol.joblib # Label encoder for "protocol_type"


2️⃣ Install Dependencies
pip install -r requirements.txt


(If missing, install manually: pip install joblib pandas scikit-learn tkinter)

3️⃣ Run the Application
python gui_app.py

📊 Dataset

KDD Cup 99 Dataset used for training & testing

41 features describing network traffic

Target classes: Normal or Attack

🔗 Learn More

📜 License

This project is licensed under the MIT License – free to use, modify, and distribute.