from flask import Flask, request, render_template_string
import os
import pickle  # VULNERABILITY: pickle usage

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials (HIGH severity)
DATABASE_PASSWORD = "SuperSecret123!"  
API_KEY = "sk-1234567890abcdefghijklmnop"

# VULNERABILITY 2: Hardcoded secret key
app.secret_key = "my-secret-key-12345"

# SECURE: Read from environment variable
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")

@app.route('/')
def home():
    return render_template_string('''
        <h1>Welcome to Gatekeeper Demo</h1>
        <form action="/search" method="get">
            <input type="text" name="query" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
        <br>
        <form action="/eval" method="post">
            <input type="text" name="code" placeholder="Enter code...">
            <button type="submit">Execute</button>
        </form>
    ''')

# VULNERABILITY 3: User input directly in template (XSS)
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Direct rendering without escaping - XSS vulnerability
    return render_template_string(f"<h2>Results for: {query}</h2>")

# VULNERABILITY 4: Use of eval() - Remote Code Execution
@app.route('/eval', methods=['POST'])
def evaluate():
    user_input = request.form.get('code', '')
    try:
        result = eval(user_input)  # CRITICAL: arbitrary code execution
        return f"Result: {result}"
    except Exception as e:
        return f"Error: {e}"

# VULNERABILITY 5: Insecure deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data', '')
    try:
        obj = pickle.loads(data.encode())  # CRITICAL: pickle vulnerability
        return str(obj)
    except:
        return "Invalid data"

if __name__ == '__main__':
    # VULNERABILITY 6: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
