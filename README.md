# Nexus Security (AI-Enhanced DevSecOps)

This project provides an AI-powered intelligence layer for DevSecOps pipelines. It ingests scan results (SARIF), triages findings using an LLM (DeepSeek Coder via Ollama), prioritizes risks, verifies them with Red-Team agents, and attempts automated self-healing via Pull Requests.

## Features (The 6-Phase Flow)

1. **Phase 1: Ingestion & Fast Scanning (Shift-Left)**
    - "Thin Adapters" run parallel scans (Semgrep, Gitleaks, Checkov, Trivy).
    - Asynchronously posts results to the Brain Orchestrator (`/triage`) to avoid blocking builds.

2. **Phase 2: Agentic Orchestration (The Brain)**
    - **Orchestrator Service**: Manages the workflow state and coordinates specialized microservices.
    - **Analysis Service**: Distinguishes True Positives (TP) from False Positives (FP) using context-aware LLM analysis.
    - **Scanner Service**: Handles parsing of various tool outputs.

3. **Phase 3: Verification Sandbox (The Safety Net)**
    - **Red-Team Logic**: Generates and runs Proof-of-Concept (PoC) exploits to verify exploitability.
    - **Sandbox Service**: Executes PoCs and patches in an ephemeral, secure Docker environment.

4. **Phase 4: Self-Healing (Automated Fixing)**
    - **Remediation Service**: Generates code patches for verified vulnerabilities.
    - **Consolidated PR**: Commits fixes to a stable branch (`ai-security-fixes`) and updates a single "Security Fixes" Pull Request to avoid spamming the repository.

5. **Phase 5: Feedback Loop (Continuous Learning)**
    - Developers review fixes in the Dashboard.
    - Feedback ("True Positive", "False Positive") is saved for future model fine-tuning.

6. **Phase 6: Observability & Insights**
    - **Live Dashboard**: Real-time view of security posture, active scans, and threat trends.
    - **Centralized Logging**: Aggregated logs via **Loki** & **Promtail** for deep debugging.
    - **Metrics**: **Grafana** dashboards for system health.

## Architecture

The system is built as a set of Dockerized microservices:

- **Orchestrator** (`:8000`): The central API gateway and workflow manager (FastAPI + LangGraph).
- **Scanner** (`:8002`): Runs security tools and parses reports.
- **Analysis** (`:8003`): AI logic for triaging findings.
- **Remediation** (`:8004`): AI logic for generating fixes.
- **Sandbox** (`:8005`): Isolated environment for verifying exploits and patches.
- **Database**:
  - **PostgreSQL**: Structured data (Findings, Scans, Feedback).
  - **Redis**: High-speed caching & Message Queue.
- **Dashboard** (`:8001`): Modern Web UI for management and visualization.
- **Observability**: Grafana (`:3000`), Loki, Promtail.

## Configuration

Create a `.env` file in the root directory. Use the following template:

```ini
# --- Secrets (Replace with actual values) ---
GITHUB_TOKEN=<your-github-token>

# --- Database & Redis (Docker Defaults) ---
DATABASE_URL=postgresql://postgres:password@db:5432/security_brain
POSTGRES_PASSWORD=password
REDIS_URL=redis://redis:6379/0

# --- LLM Settings (Ollama) ---
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=deepseek-coder-v2-lite
LLM_API_KEY=ollama
# Optional Tuning
LLM_MAX_TOKENS=2048
LLM_TEMPERATURE=0.1
LLM_TIMEOUT=300

# --- Orchestrator Settings ---
AI_API_KEY=default-dev-key
HUMAN_INTERACTION=false
```

## Setup

1. **Prerequisites**: Docker & Docker Compose.
2. **Environment Variables**:
    Ensure `GITHUB_TOKEN` is set in your environment (for PR creation).

    ```bash
    export GITHUB_TOKEN=your_github_token
    ```

3. **Start the Stack**:

    ```bash
    docker-compose up -d --build
    ```

    *Note: Ensure Ollama is running and has the `deepseek-coder-v2-lite` (or configured) model pulled.*

4. **Access Services**:
    - **Security Dashboard**: [http://localhost:8001](http://localhost:8001)
    - **Grafana (Metrics)**: [http://localhost:3000](http://localhost:3000) (Default: `admin`/`admin`)
    - **Orchestrator API**: [http://localhost:8000/docs](http://localhost:8000/docs)

## Usage

### Using Adapters

Copy the relevant adapter from `adapters/` to your project's CI/CD configuration.

- **GitHub**: `.github/workflows/ai-scan.yml` (Runs scanners in parallel).

### CI/CD Integration (GitHub Actions)

To allow GitHub Actions to communicate with your local or hosted Brain, you must set the following **Repository Secrets**:

1. Go to your GitHub Repo -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Add the following secrets:
    - `AI_API_KEY`: The API Request Header for authentication (Default: `default-dev-key` configured in `.env`).
    - `AI_URL`: The public endpoint where your Orchestrator is reachable (e.g., `https://<your-ngrok-id>.ngrok-free.app`).

### Remote Access (Ngrok Tutorial)

Since the Brain runs locally on `localhost:8000`, GitHub Actions cannot reach it directly. Use `ngrok` to create a secure tunnel.

1. **Install Ngrok**:

    ```bash
    brew install ngrok/ngrok/ngrok
    ```

2. **Authenticate** (Sign up at [ngrok.com](https://ngrok.com) to get your token):

    ```bash
    ngrok config add-authtoken <YOUR_TOKEN>
    ```

3. **Start Tunnel**:
    Forward port 8000 (Orchestrator):

    ```bash
    ngrok http 8000
    ```

4. **Copy URL**:
    Copy the "Forwarding" URL (e.g., `https://a1b2-c3d4.ngrok-free.app`).
5. **Update GitHub Secret**:
    Paste this URL into the `AI_URL` secret in your GitHub repository.

### Manual Test

Upload a SARIF file via the Dashboard or use CURL to trigger the Orchestrator:

```bash
curl -X POST http://localhost:8000/triage \
  -F "project=MyProject" \
  -F "sha=abcdef" \
  -F "token=dummy_token" \
  -F "files=@scan.sarif"
```

## Feedback & Training

Feedback data is stored in PostgreSQL. Future updates will include automated export scripts for model fine-tuning.
