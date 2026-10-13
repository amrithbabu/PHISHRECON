import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from feature_extractor import extract_features
import pickle

data = pd.read_csv("dataset.csv")

X = [extract_features(url) for url in data['url']]
y = data['label']

model = RandomForestClassifier()
model.fit(X, y)

with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained!")
