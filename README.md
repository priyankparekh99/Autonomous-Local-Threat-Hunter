# 🛡️ Autonomous Local AI Threat Hunter & Log Analyzer

> An air-gapped, privacy-first cybersecurity threat hunting agent powered by **Open-Weight Models (Qwen 2.5 / Gemma 2)**, **LangGraph**, **DuckDB**, and **Ollama**.

[![Hacktoberfest 2026](https://img.shields.io/badge/Hacktoberfest-2026-orange.svg)](https://hacktoberfest.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## 🚀 Overview

Modern Security Operations Centers (SOCs) face a dilemma: uploading massive volumes of sensitive telemetry (access logs, syslogs, cloud trails) to third-party cloud LLM APIs risks severe data leakage. 

**Autonomous Local Threat Hunter** solves this by running 100% locally and air-gapped on your hardware. It uses **DuckDB** for lightning-fast in-memory analytical querying, **LangGraph** for deterministic agentic reasoning loops, and **Ollama** to run open-weight models securely offline.

---

## 🏗️ Architecture Pipeline
┌─────────────────────────┐
│ Raw Logs (Nginx / SSH / │
│ JSON Telemetry)         │
└─────────────────────────┘
│
▼
┌─────────────────────────┐      ┌─────────────────────────┐
│ In-Memory SQL Engine    │<────>│ Query Tool Node         │
│ (DuckDB Fast Analytical)│      │ (Detects anomalous bursts)│
└─────────────────────────┘      └─────────────────────────┘
▲
│ LangGraph
▼ Loop
┌─────────────────────────┐      ┌─────────────────────────┐
│ Executive SOC Markdown  │<─────│ Local LLM (Qwen 2.5 7B) │
│ Incident & Threat Report│      │ Analyzes IOCs & Mitigations│
└─────────────────────────┘      └─────────────────────────┘

## ✨ Key Features

- **100% Air-Gapped & Private:** Zero external API calls. Your security logs and threat intelligence never leave your machine.
- **Agentic State Graph:** Built with **LangGraph** to ensure robust, predictable node transitions (Ingest ➔ Query & Analyze ➔ Report).
- **Fast Analytical Engine:** Leverages **DuckDB** to execute high-performance relational queries over raw JSON logs before passing data to the local LLM.
- **Structured JSON Outputs:** Forces open-weight models to return strict schemas for automated SIEM ingestion.

---

## ⚙️ Prerequisites & Installation

1. **Install Ollama:**
   Download and install [Ollama](https://ollama.com/), then pull your preferred open-weight model:
   ```bash
   ollama pull qwen2.5:7b
