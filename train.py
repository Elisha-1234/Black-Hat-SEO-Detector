import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# 1. Create 'models' folder if not exists
if not os.path.exists('models'):
    os.makedirs('models')

# 2. Sample Data (To train the model initially)
X_train = [
    "free money winner lottery prize claim now",  # Spam
    "buy viagra cialis cheap pills online",       # Spam
    "click here to win iphone free",              # Spam
    "official government website for visa",       # Safe
    "university admission open for students",     # Safe
    "python programming tutorial for beginners",  # Safe
    "casino gambling poker free bonus chips",     # Spam
    "contact support for your account issue",     # Safe
    "download cracked software free keygen",      # Spam
    "welcome to our official blog page"           # Safe
]
y_train = [1, 1, 1, 0, 0, 0, 1, 0, 1, 0]  # 1 = Spam, 0 = Safe

# 3. Vectorization (Convert text to numbers)
print("🧠 Training AI Model...")
vectorizer = TfidfVectorizer()
X_vectors = vectorizer.fit_transform(X_train)

# 4. Train Model (Random Forest)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_vectors, y_train)

# 5. Save Model & Vectorizer
print("💾 Saving models to 'models/' folder...")
with open('models/blackhat_model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('models/tfidf_vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("✅ Success! Model is ready. Now run 'python app.py'.")