import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Load encoders and scaler
print("[STEP] Loading trained model and encoders...")

try:
    le_protocol = joblib.load("encoders/le_protocol_type.joblib")
    le_service = joblib.load("encoders/le_service.joblib")
    le_flag = joblib.load("encoders/le_flag.joblib")
    le_label = joblib.load("encoders/le_label.joblib")
    scaler = joblib.load("models/scaler.joblib")
    model = joblib.load("models/ids_model.joblib")  # Assuming this is your trained model
except FileNotFoundError as e:
    print(f"[ERROR] Missing file: {e.filename}")
    exit(1)

print("[STEP] Encoders and model loaded.")

# Sample input (REPLACE with real-time data in deployment)
sample_input = {
    'duration': 0,
    'protocol_type': 'tcp',
    'service': 'http',
    'flag': 'SF',
    'src_bytes': 181,
    'dst_bytes': 5450,
    'land': 0,
    'wrong_fragment': 0,
    'urgent': 0,
    'hot': 0,
    'num_failed_logins': 0,
    'logged_in': 1,
    'num_compromised': 0,
    'root_shell': 0,
    'su_attempted': 0,
    'num_root': 0,
    'num_file_creations': 0,
    'num_shells': 0,
    'num_access_files': 0,
    'num_outbound_cmds': 0,
    'is_host_login': 0,
    'is_guest_login': 0,
    'count': 511,
    'srv_count': 511,
    'serror_rate': 0.00,
    'srv_serror_rate': 0.00,
    'rerror_rate': 0.00,
    'srv_rerror_rate': 0.00,
    'same_srv_rate': 1.00,
    'diff_srv_rate': 0.00,
    'srv_diff_host_rate': 0.00,
    'dst_host_count': 255,
    'dst_host_srv_count': 255,
    'dst_host_same_srv_rate': 1.00,
    'dst_host_diff_srv_rate': 0.00,
    'dst_host_same_src_port_rate': 0.00,
    'dst_host_srv_diff_host_rate': 0.00,
    'dst_host_serror_rate': 0.00,
    'dst_host_srv_serror_rate': 0.00,
    'dst_host_rerror_rate': 0.00,
    'dst_host_srv_rerror_rate': 0.00
}

# Convert to DataFrame
df_input = pd.DataFrame([sample_input])

# Encode categorical features
df_input['protocol_type'] = le_protocol.transform(df_input['protocol_type'])
df_input['service'] = le_service.transform(df_input['service'])
df_input['flag'] = le_flag.transform(df_input['flag'])

# Scale features
X_scaled = scaler.transform(df_input)

# Predict
prediction = model.predict(X_scaled)
prediction_label = le_label.inverse_transform(prediction)

print(f"[RESULT] Prediction: {prediction_label[0]}")
