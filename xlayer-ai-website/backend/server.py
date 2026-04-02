from flask import Flask, request, jsonify
from flask_cors import CORS
import time

# Initialize Flask App
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing
CORS(app)

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    Handles chat messages from the frontend.
    Accepts a POST request with a JSON body: {"message": "user input"}
    """
    try:
        data = request.json
        user_message = data.get('message', '').strip()

        if not user_message:
            return jsonify({'error': 'Message cannot be empty.'}), 400

        # --- Mock XIC LLM Integration ---
        # In a real application, you would call your LLM here.
        # For now, we return a mock response based on keywords.
        time.sleep(1) # Simulate network delay
        
        response_text = f"XIC mock response to: '{user_message}'"
        if "phishshield" in user_message.lower():
            response_text = "PhishShield is our real-time phishing detection tool with a 98% accuracy rate."
        elif "reconbot" in user_message.lower():
            response_text = "ReconBot automates network reconnaissance and vulnerability mapping for ethical hackers."
        elif "cve" in user_message.lower():
            response_text = "CVE-Explain provides comprehensive analysis of Common Vulnerabilities and Exposures, offering impact analysis and patch recommendations."

        return jsonify({'response': response_text})

    except Exception as e:
        print(f"Error in /api/chat: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

@app.route('/api/contact', methods=['POST'])
def contact():
    """
    Handles contact form submissions.
    Accepts a POST request with a JSON body: {"name": "...", "email": "...", "message": "..."}
    """
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        message = data.get('message')

        if not all([name, email, message]):
             return jsonify({'error': 'All fields are required.'}), 400

        # --- Mock Submission Handling ---
        # In a real application, you would email this data or save it to a database.
        print("--- CONTACT FORM SUBMISSION ---")
        print(f"Name: {name}")
        print(f"Email: {email}")
        print(f"Message: {message}")
        print("-----------------------------")

        return jsonify({'message': 'Your message has been received! We will get back to you shortly.'})

    except Exception as e:
        print(f"Error in /api/contact: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500


if __name__ == '__main__':
    # The 'host' parameter makes the server accessible on your network.
    # The 'port' can be any available port.
    app.run(host='0.0.0.0', port=5001, debug=True)