# Web Security Scanner
A modern web application security scanner built with Python/Flask.

## 🚀 Features

### Security Analysis
- **Security Headers Analysis**
  - HSTS (HTTP Strict Transport Security)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Content Security Policy
  - Referrer Policy
  - Permissions Policy

- **SSL/TLS Configuration**
  - Protocol version detection
  - Certificate information
  - Cipher suite analysis
  - Certificate expiry dates

- **Vulnerability Detection**
  - Directory traversal attempts
  - Sensitive file exposure
  - Common web vulnerabilities
  - Information disclosure

- **Technology Stack Detection**
  - CMS detection (WordPress, Drupal, Joomla)
  - Framework detection (React, Angular, Vue.js)
  - Server technology detection
  - Database technology detection

- **Information Gathering**
  - Robots.txt analysis
  - Sitemap analysis
  - Port scanning (common ports)
  - Server information disclosure

### Additional Features
- **Real-time scanning** - No background processes needed
- **JSON report download** - Export results in structured format
- **API endpoints** - RESTful API for integration
- **Modern UI** - Bootstrap-based responsive interface
- **Cloud-ready** - Deployable on free platforms

## 🛠️ Technology Stack

- **Backend**: Python 3.9+, Flask
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript
- **Dependencies**: requests, ssl, socket (built-in Python modules)
- **Deployment**: Vercel, Render, Railway, Heroku

## 📦 Installation

### Local Development

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd WebSecScan
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements_web.txt
   ```

3. **Run the application**
   ```bash
   python web_app.py
   ```

4. **Access the application**
   - Open http://localhost:5000 in your browser

## 🚀 Deployment

### Vercel (Recommended - Free)

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Deploy**
   ```bash
   vercel
   ```

3. **Follow the prompts and your app will be live!**

### Render (Free Tier)

1. **Connect your GitHub repository to Render**
2. **Create a new Web Service**
3. **Configure:**
   - **Build Command**: `pip install -r requirements_web.txt`
   - **Start Command**: `python web_app.py`
   - **Environment**: Python 3

### Railway (Free with $5 credit)

1. **Connect your GitHub repository to Railway**
2. **Railway will auto-detect Python and deploy**

## 🔧 API Usage

### Perform a Scan
```bash
curl -X POST https://your-app.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Get Scan Results
```bash
curl https://your-app.vercel.app/api/scan/{scan_id}
```

## 📊 Scan Results

The scanner provides comprehensive results including:

- **Security Headers**: Analysis of all security-related HTTP headers
- **SSL/TLS Info**: Certificate details, protocol versions, cipher suites
- **Vulnerabilities**: Found security issues with severity levels
- **Information Disclosure**: Exposed sensitive information
- **Technology Stack**: Detected technologies and frameworks
- **Open Ports**: Common ports that are accessible
- **Robots.txt**: Analysis of robots.txt file
- **Sitemap**: Analysis of sitemap.xml file
- **Recommendations**: Actionable security recommendations

## 🔒 Security Features

### What the Scanner Checks

1. **Security Headers**
   - Missing or misconfigured security headers
   - HSTS implementation
   - Content Security Policy
   - Clickjacking protection

2. **SSL/TLS Security**
   - Certificate validity
   - Protocol versions (TLS 1.0/1.1 detection)
   - Weak cipher suites
   - Certificate expiry

3. **Common Vulnerabilities**
   - Directory traversal attempts
   - Sensitive file access
   - Error information disclosure
   - Version information exposure

4. **Information Disclosure**
   - Server version information
   - Technology stack details
   - Error messages
   - Debug information

## 🎯 Use Cases

- **Web Application Security Testing**
- **Security Headers Audit**
- **SSL/TLS Configuration Review**
- **Technology Stack Analysis**
- **Vulnerability Assessment**
- **Security Compliance Checking**

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to scan the target website. The authors are not responsible for any misuse of this tool. 
