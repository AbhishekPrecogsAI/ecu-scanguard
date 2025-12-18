<p align="center">
  <img src="public/logo.png" alt="Precogs AI" width="80" height="80">
</p>

<h1 align="center">ECU-SAST</h1>

<p align="center">
  <strong>Automotive Static Application Security Testing Platform</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## Overview

**ECU-SAST** is an enterprise-grade Static Application Security Testing (SAST) platform purpose-built for the automotive industry. It provides comprehensive vulnerability detection, SBOM generation, and compliance validation for ECU firmware, embedded systems, and automotive software.

Built by [Precogs AI](https://www.precogs.ai), ECU-SAST combines traditional pattern-based analysis with AI-powered vulnerability detection to deliver actionable security insights with minimal false positives.

## Features

### 🔍 Security Analysis
- **AI-Powered Vulnerability Detection** — Leverages LLMs for context-aware security analysis
- **Automotive-Specific Rules** — MISRA C/C++, AUTOSAR, ISO 21434 compliance checks
- **Binary Analysis** — Firmware and ECU binary vulnerability scanning
- **Multi-Format Support** — C, C++, Python, Rust, VBF, ARXML, HEX, S-Record

### 📦 Software Bill of Materials (SBOM)
- Automated component discovery
- License compliance tracking
- Dependency vulnerability mapping
- Export to CycloneDX and SPDX formats

### ✅ Compliance & Reporting
- ISO 21434 cybersecurity compliance
- UNECE WP.29 regulation support
- PDF report generation
- Risk scoring and prioritization

### 🤖 AI Copilot
- Interactive security assistant
- Remediation guidance
- Code fix suggestions
- Vulnerability explanation

## Quick Start

### Prerequisites
- Node.js 18+ and npm
- Supabase account (for backend services)

### Installation

```bash
# Clone the repository
git clone https://github.com/Sharmarajnish/ecu-sast.git
cd ecu-sast

# Install dependencies
npm install

# Start development server
npm run dev
```

The application will be available at `http://localhost:8080`

### Environment Setup

Create a `.env` file with your Supabase credentials:

```env
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

## Architecture

```
ecu-sast/
├── src/
│   ├── components/     # Reusable UI components
│   ├── pages/          # Application pages
│   ├── hooks/          # Custom React hooks
│   ├── services/       # Analysis and API services
│   └── integrations/   # Supabase client
├── supabase/
│   └── functions/      # Edge functions for scanning
├── examples/           # Sample files for testing
└── public/             # Static assets
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, TypeScript, Vite |
| Styling | Tailwind CSS, shadcn/ui |
| State | TanStack Query |
| Backend | Supabase (Auth, Database, Edge Functions) |
| AI | Google Gemini API |

## Documentation

Access the built-in documentation at `/documentation` in the running application, which includes:

- Getting started guides
- API reference
- Compliance frameworks
- Integration tutorials

## Deployment

### Production Build

```bash
npm run build
npm run preview
```

### Cloud Deployment

The application is designed for deployment on:
- Vercel
- Netlify
- Supabase Hosting
- Any static hosting platform

## Security

For security vulnerabilities, please contact [security@precogs.ai](mailto:security@precogs.ai).

## License

Proprietary — © 2024 Precogs AI. All rights reserved.

---

<p align="center">
  <strong>Built with ❤️ by <a href="https://www.precogs.ai">Precogs AI</a></strong>
</p>
