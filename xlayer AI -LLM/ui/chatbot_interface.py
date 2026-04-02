# ui/chatbot_interface.py

import streamlit as st
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from xic.forward_pass import generate_response

# Set page config
st.set_page_config(
    page_title="XLayer AI Chatbot",
    page_icon="🛡️"
)

st.title("XLayer AI - Cybersecurity Chatbot")
st.markdown("Ask me anything about cybersecurity (phishing, malware, XSS, CVE, etc.)")

# Text input
user_input = st.text_input("🔐 Enter your question:")

# Response section
if user_input:
    response = generate_response(user_input)
    st.markdown("###  Response:")
    st.success(response)