# 🛡️ AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> **AICTE/SIH Specification** — A production-grade email forensics platform that combines deep header analysis, hop-by-hop geolocation tracing, sender authentication (SPF/DKIM/DMARC), AI-powered threat classification, and graph-based campaign attribution.

## ✨ Features

- **Raw Email Forensics**: Ingest `.eml` files, compute cryptographic hashes (MD5/SHA-1/SHA-256), parse all MIME headers, extract attachments and embedded URLs
- **Hop-by-Hop Geolocation**: Reconstruct SMTP relay chain, classify private vs public IPs, map every hop geographically
- **Sender Authentication**: Real-time SPF, DKIM, and DMARC validation via DNS queries
- **AI Threat Detection**: NLP-based phishing/BEC classification, homoglyph detection, URL analysis
- **Composite Risk Scoring**: Explainable 0-100 risk score with weighted multi-factor analysis
- **Graph Attribution**: Campaign clustering and infrastructure mapping (NetworkX / Neo4j)
- **Interactive Dashboard**: World hop map (Leaflet), network graph (Cytoscape), risk gauges
- **Forensic Reports**: Court-admissible PDF generation with evidence integrity stamps

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Access
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Frontend**: http://localhost:5173

## 🏗️ Architecture

```
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application factory
│   │   ├── config.py            # Pydantic Settings configuration
│   │   ├── database.py          # SQLAlchemy async engine (SQLite/PostgreSQL)
│   │   ├── models.py            # ORM models
│   │   ├── schemas.py           # Pydantic v2 request/response schemas
│   │   ├── api/
│   │   │   └── routes.py        # REST API endpoints
│   │   └── services/
│   │       ├── eml_parser.py    # Email parsing & hash computation
│   │       ├── hop_tracer.py    # SMTP relay chain analysis
│   │       ├── geo_resolver.py  # IP geolocation (MaxMind/mock)
│   │       ├── auth_engine.py   # SPF/DKIM/DMARC validation
│   │       ├── nlp_engine.py    # AI threat classification
│   │       ├── risk_scorer.py   # Composite risk scoring
│   │       └── graph_engine.py  # Campaign graph attribution
│   ├── tests/
│   └── requirements.txt
├── frontend/                    # React + Vite + Tailwind
├── data/
│   ├── samples/                 # Sample .eml files for testing
│   └── models/                  # Serialized ML models
├── docker-compose.yml           # Optional PostgreSQL + Neo4j
└── .env.example                 # Environment configuration template
```

## 🔧 Configuration

The platform runs **100% locally out-of-the-box** with zero configuration. All external services have built-in mock fallbacks:

| Service | Default | Production |
|---------|---------|------------|
| Database | SQLite | PostgreSQL via `DATABASE_URL` |
| Graph DB | NetworkX (in-memory) | Neo4j via `NEO4J_URI` |
| GeoIP | Mock resolver | MaxMind GeoLite2 via `GEOIP_DB_PATH` |
| IP Reputation | Mock scores | AbuseIPDB via `ABUSEIPDB_API_KEY` |

Copy `.env.example` to `.env` and configure as needed.

## 📄 License

MIT License — Built for AICTE/SIH 2024
