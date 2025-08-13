import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Load the preprocessed data
df = pd.read_csv("processed_train.csv")

# Separate features and label
X = df.drop("label", axis=1)
y = df["label"]

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("[INFO] Accuracy:", accuracy_score(y_test, y_pred))
print("[INFO] Classification Report:")
print(classification_report(y_test, y_pred))

# Save model
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/ids_model.joblib")
print("[DONE] Model saved to models/ids_model.joblib")
