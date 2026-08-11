# Janus PQC Engine - Web Dashboard

A React-based dashboard for the Janus research platform. It provides real-time monitoring, policy review, simulation, and AI-assisted draft generation.

## Features

- Quantum threat dashboard with decision and posture summaries
- Request simulator for demo cryptographic policy evaluation
- Policy editor with manual review and hot-reload workflows
- Policy Assistant for natural-language draft YAML generation

## Tech stack

- React 18+ with TypeScript
- Vite
- Tailwind CSS
- Zustand
- Axios
- Monaco Editor
- Recharts
- Lucide React

## Prerequisites

- Node.js 18+ and npm
- Go 1.25+ for the backend
- Janus Go backend running on port 8080

## Installation

```bash
npm install
```

Optional API endpoint override:

```bash
echo "VITE_API_URL=http://localhost:8080" > .env
```

## Running the development server

1. Start the Janus backend from the repository root:

```bash
go run cmd/pq-engine/main.go
```

2. Start the React development server:

```bash
npm run dev
```

3. Open `http://localhost:5173`

## API endpoints

- `POST /api/evaluate` - Evaluate cryptographic configuration
- `GET /api/metrics` - Get current metrics
- `GET /api/policy` - Get current policy YAML
- `PUT /api/policy` - Update policy
- `POST /api/ai/generate` - Generate draft YAML from natural language

## Policy Assistant

The assistant requires an `OPENAI_API_KEY` environment variable for live generation. Without it, the system returns a fallback draft policy.

Generated YAML should always be reviewed in the Policy Editor before being applied.

## Acceptance criteria

- `npm run dev` shows the dashboard at `localhost:5173`
- The Request Simulator returns a valid algorithm from the Go backend
- Editing YAML and saving updates `configs/policy.yaml`
- The assistant generates draft YAML for review
- Dashboard threat indicators update as policies change

## License

Part of the Janus project.
