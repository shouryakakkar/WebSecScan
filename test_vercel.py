from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Vercel!"

@app.route('/test')
def test():
    return "Test endpoint working"

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "environment": "vercel"})

if __name__ == "__main__":
    app.run() 