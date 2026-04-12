import pandas as pd
from sklearn.model_selection import cross_val_score, KFold
from sklearn.ensemble import RandomForestClassifier

data = pd.read_csv("Phishing_Legitimate_full.csv")

X = data.drop(["CLASS_LABEL", "id", "Index"], axis=1, errors="ignore")
y = data["CLASS_LABEL"]

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

kf = KFold(n_splits=5, shuffle=True, random_state=42)

scores = cross_val_score(model, X, y, cv=kf)

accuracy = scores.mean() * 100
accuracy = round(accuracy, 2)

print("Model Accuracy:", accuracy)
