from flask import Flask, request, jsonify
import requests
import logging

app = Flask(__name__)

# Configure Logging
logging.basicConfig(filename="api_logs.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# API Proxy Route
@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy():
    target_url = request.args.get('url')  # Example: /proxy?url=https://jsonplaceholder.typicode.com/posts
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    method = request.method
    headers = {key: value for key, value in request.headers if key.lower() != 'host'}
    data = request.get_json() if method in ['POST', 'PUT'] else None

    try:
        response = requests.request(method, target_url, headers=headers, json=data)
        
        # Log request & response
        log_entry = f"""
        REQUEST:
        Method: {method}
        URL: {target_url}
        Headers: {headers}
        Body: {data}

        RESPONSE:
        Status: {response.status_code}
        Body: {response.text}
        """
        logging.info(log_entry)
        
        return response.text, response.status_code, response.headers.items()
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({"error": "Failed to connect to target URL"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
