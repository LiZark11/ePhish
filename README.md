# ePhish - Digital Forensic Platform for Phishing and Malware Analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Made%20with-Docker-blue.svg)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)](#)

**ePhish** is an advanced digital forensic platform designed for comprehensive analysis of phishing emails and embedded malware. It combines rule-based heuristics, Natural Language Processing (NLP) techniques, and machine learning models to detect, analyze, and report on malicious email threats.

## Features

- **Real-time Dashboard:** Monitor threat levels, analysis statistics, and recent cases.
- **Phishing Email Analysis:** Detect phishing attempts in `.eml`, `.msg`, and `.csv` files using DistilBERT NLP model and custom rules.
- **Malware Email Analysis:** Identify hidden malware within email content and attachments.
- **Batch Processing:** Analyze large datasets of emails from CSV files efficiently.
- **Progress Tracking:** Real-time progress bar and timer during analysis.
- **Detailed Reporting:** Comprehensive forensic reports generated in PDF format.
- **AI-Powered Explanations:** Understandable explanations for analysis results.
- **Microservices Architecture:** Scalable and maintainable design using Docker containers.
- **SQL Database Integration:** Store and query analysis logs and results.

## Tech Stack

- **Frontend:** React.js, Tailwind CSS, Lucide Icons
- **Backend:** FastAPI, Uvicorn
- **Analyzer:** Flask, DistilBERT (Transformers), Pandas, Scikit-learn
- **Database:** MySQL
- **Deployment:** Docker, Docker Compose
- **Reporting:** ReportLab (for PDF generation)
- **Security:** SQLAlchemy ORM, Pydantic Validation

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/LiZark11/ePhish.git
   cd ePhish
   '''
2. **Build and Run with Docker Compose:**
   '''bash
    docker compose up --build
   '''
   This will build the necessary Docker images and start all services (frontend, backend, analyzer, MySQL)
3. **Access the Application:**
    - **Frontend (Dashboard):** [http://localhost:3000](http://localhost:3000)
    - **Backend API:** [http://localhost:8000](http://localhost:8000)
    - **Analyzer Service:** [http://localhost:5000](http://localhost:5000)
   
## Usage:
1. Navigate to http://localhost:3000.
2. Use the Dashboard to view overall statistics.
3. Go to Email Phishing to upload .eml, .msg, or .csv files for phishing analysis.
4. Go to Email Malware to upload emails or attachments for malware detection.
5. View detailed results, including confidence scores, indicators, and severity levels.
6. Utilize the AI assistant for explanations of findings.

## Architecture:
ePhish follows a microservices architecture:

- frontend: React application providing the user interface.
- backend: FastAPI application handling API requests, database interactions, and orchestrating analysis tasks.
- analyzer: Flask application performing core analysis using NLP and ML models.
- mysql-db: Persistent storage for analysis logs and results.

## License:

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Author
LiZark11
