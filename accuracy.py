import pandas as pd
import pickle
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score


data = pd.read_csv("Phishing_Legitimate_full.csv")


X = data.drop(["CLASS_LABEL"], axis=1)
y = data["CLASS_LABEL"]

model = pickle.load(open("phishing_model.pkl", "rb"))

scores = cross_val_score(model, X, y, cv=5)

accuracy = scores.mean() * 100
accuracy = round(accuracy, 2)

print("Model Accuracy:", accuracy)