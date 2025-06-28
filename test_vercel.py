from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def hello():
    return jsonify({"message": "Hello from Vercel!", "status": "success"})

@app.route('/test')
def test():
    return jsonify({"message": "Test endpoint working", "status": "success"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "environment": "vercel"})

if __name__ == "__main__":
    app.run(debug=True) 