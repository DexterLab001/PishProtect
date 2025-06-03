import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000"

st.title("🔐 Cyber Threat Detection System")
st.markdown("Use this tool to test intrusion, phishing emails, and phishing URLs.")

option = st.selectbox("Choose detection type:", ["Intrusion", "Phishing Email", "Phishing URL"])

# --- Intrusion Detection --- #
if option == "Intrusion":
    st.subheader("🚨 Intrusion Detection")
    features_input = st.text_input("Enter 41 comma-separated features:")

    if st.button("Predict Intrusion"):
        try:
            features = [float(x.strip()) for x in features_input.split(",")]
            if len(features) != 41:
                st.error("❌ You must enter exactly 41 features.")
            else:
                response = requests.post(f"{API_URL}/predict_intrusion", json={"features": features})
                if response.status_code == 200:
                    result = response.json()
                    st.success(f"Prediction: {result.get('prediction')}")
                else:
                    st.error(f"Server Error: {response.json().get('detail', 'Unknown error')}")
        except Exception as e:
            st.error(f"Error: {e}")

# --- Phishing Email Detection --- #
elif option == "Phishing Email":
    st.subheader("📧 Phishing Email Detection")
    email_text = st.text_area("Paste suspicious email text:")

    if st.button("Predict Email"):
        try:
            response = requests.post(f"{API_URL}/predict_phishing_email", json={"email_text": email_text})
            if response.status_code == 200:
                result = response.json()
                st.success(f"Prediction: {result.get('prediction')}")
            else:
                st.error(f"Server Error: {response.json().get('detail', 'Unknown error')}")
        except Exception as e:
            st.error(f"Error: {e}")

# --- Phishing URL Detection --- #
elif option == "Phishing URL":
    st.subheader("🌐 Phishing URL Detection")
    url_input = st.text_input("Enter suspicious URL (e.g., http://example.com/login):")

    if st.button("Predict URL"):
        try:
            response = requests.post(f"{API_URL}/predict_phishing_url", json={"url": url_input})
            if response.status_code == 200:
                result = response.json()
                st.success(f"Prediction: {result.get('prediction')}")
            else:
                st.error(f"Server Error: {response.json().get('detail', 'Unknown error')}")
        except Exception as e:
            st.error(f"Error: {e}")
