import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

def preprocess_data(df):
    # Define expected columns
    col_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'label'
    ]

    print(f"[INFO] Original number of columns: {len(df.columns)}")

    # Trim extra columns if present
    if len(df.columns) > len(col_names):
        print("[INFO] Dropping extra columns to match expected feature count.")
        df = df.iloc[:, :len(col_names)]
    elif len(df.columns) < len(col_names):
        raise ValueError("Dataset has fewer columns than expected.")

    df.columns = col_names

    # Encode categorical features
    encoders_dir = "encoders"
    os.makedirs(encoders_dir, exist_ok=True)

    for col in ['protocol_type', 'service', 'flag']:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        joblib.dump(le, f"{encoders_dir}/le_{col}.joblib")
        print(f"[INFO] Saved encoder: le_{col}.joblib")

    # Encode label
    le_label = LabelEncoder()
    df['label'] = le_label.fit_transform(df['label'])
    joblib.dump(le_label, f"{encoders_dir}/le_label.joblib")
    print(f"[INFO] Saved encoder: le_label.joblib")

    # Feature scaling
    X = df.drop("label", axis=1)
    y = df["label"]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save the scaler
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(scaler, f"{models_dir}/scaler.joblib")
    print(f"[INFO] Saved scaler: scaler.joblib")

    # Return processed dataframe
    processed_df = pd.DataFrame(X_scaled, columns=X.columns)
    processed_df["label"] = y.values

    return processed_df

if __name__ == "__main__":
    print("[STEP] Loading data...")

    file_path = "KDDTrain+.txt"  # Replace with actual path if needed

    try:
        df = pd.read_csv(file_path, header=None)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        exit(1)

    print("[STEP] Data loaded. Now preprocessing...")

    processed_df = preprocess_data(df)

    output_path = "processed_train.csv"
    processed_df.to_csv(output_path, index=False)

    print(f"[DONE] Preprocessing complete. Saved to {output_path}")
