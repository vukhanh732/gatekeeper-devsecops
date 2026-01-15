from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# SECURE: Read from environment variable
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")

@app.route('/')
def home():
    return render_template_string('''
        <h1>Welcome to Gatekeeper Demo</h1>
        <form action="/search" method="get">
            <input type="text" name="query" placeholder="Search users...">
            <button type="submit">Search</button>
        </form>
    ''')

# INTENTIONAL VULNERABILITY: SQL Injection (for demo purposes)
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # BAD PRACTICE: Direct string concatenation in SQL (simulated)
    # In real app: cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    result = f"Searching for: {query}"
    return render_template_string(f"<h2>{result}</h2><p>Results would appear here.</p>")

if __name__ == '__main__':
    # SECURE: Debug mode disabled for production
    app.run(debug=False, host='0.0.0.0', port=5000)
