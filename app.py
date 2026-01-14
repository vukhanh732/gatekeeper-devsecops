from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded AWS Secret (SAST target)
# NEVER do this in real life. We are doing this to trigger our security scanner later.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE" 

@app.route('/')
def home():
    return "<h1>The Gatekeeper Project</h1><p>Welcome to the vulnerable app.</p>"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABILITY 2: Reflected Cross-Site Scripting (XSS) (DAST target)
    # We are rendering user input directly without sanitization.
    template = f"<h2>Search Results for: {query}</h2>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
