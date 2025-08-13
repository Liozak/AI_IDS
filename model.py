# model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Load the preprocessed training data
df = pd.read_csv("processed_train.csv")


from sklearn.preprocessing import LabelEncoder

# Encode categorical features
le_protocol = LabelEncoder()
le_service = LabelEncoder()
le_flag = LabelEncoder()

df['protocol_type'] = le_protocol.fit_transform(df['protocol_type'])
df['service'] = le_service.fit_transform(df['service'])
df['flag'] = le_flag.fit_transform(df['flag'])

# Save the encoders for later use in test data
joblib.dump(le_protocol, "le_protocol.joblib")
joblib.dump(le_service, "le_service.joblib")
joblib.dump(le_flag, "le_flag.joblib")


def train_model():
    print("[STEP] Loading preprocessed data...")
    df = pd.read_csv("processed_train.csv")

    print("[STEP] Splitting into features and labels...")
    X = df.drop("label", axis=1)
    y = df["label"]

    print("[STEP] Splitting into train and validation sets...")
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[STEP] Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    print("[STEP] Evaluating model...")
    y_pred = model.predict(X_val)
    print("[RESULT] Accuracy:", accuracy_score(y_val, y_pred))
    print("[RESULT] Classification Report:\n", classification_report(y_val, y_pred))

    print("[STEP] Saving model as model.joblib...")
    joblib.dump(model, "model.joblib")
    print("[DONE] Model training complete.")

if __name__ == "__main__":
    train_model()

