# Janus PQC Engine - Web Dashboard

A modern React-based web dashboard for the Janus Post-Quantum Cryptographic Engine. This dashboard provides real-time monitoring, policy management, and AI-assisted policy generation.

## Features

- **Quantum Threat Dashboard**: Real-time monitoring of cryptographic decisions with threat level gauges
- **Request Simulator**: Test cryptographic configurations with different scenarios and risk levels
- **Policy Editor**: Monaco-based YAML editor with hot-reload capabilities
- **AI Co-Pilot**: Natural language to YAML policy generation using AI

## Tech Stack

- **Frontend**: React 18+ with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **State Management**: Zustand
- **HTTP Client**: Axios
- **Code Editor**: Monaco Editor
- **Charts**: Recharts
- **Icons**: Lucide React

## Prerequisites

- Node.js 18+ and npm
- Go 1.21+ (for the backend)
- Janus Go backend running on port 8080

## Installation

1. Install dependencies:
```bash
npm install
```

2. Configure API endpoint (optional):
```bash
# Create .env file in the web directory
echo "VITE_API_URL=http://localhost:8080" > .env
```

## Running the Development Server

1. Start the Janus Go backend:
```bash
# From the Janus root directory
go run cmd/pq-engine/main.go
```

2. Start the React development server:
```bash
npm run dev
```

3. Open your browser to `http://localhost:5173`

## Building for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

## API Endpoints

The frontend communicates with the Janus HTTP API on port 8080:

- `POST /api/evaluate` - Evaluate cryptographic configuration
- `GET /api/metrics` - Get current metrics
- `GET /api/policy` - Get current policy YAML
- `POST /api/policy` - Update policy (triggers hot-reload)
- `POST /api/ai/generate` - Generate YAML from natural language

## AI Co-Pilot

The AI Co-Pilot feature requires an OpenAI API key. Set it as an environment variable:

```bash
export OPENAI_API_KEY=your_api_key_here
```

Without the API key, the system uses a smart mock generator that responds to keywords like "EU", "IoT", "strict", etc.

## Project Structure

```
web/
├── src/
│   ├── components/
│   │   ├── Dashboard/       # Dashboard components
│   │   ├── Simulator/       # Request simulator
│   │   ├── PolicyEditor/    # YAML policy editor
│   │   ├── AICopilot/       # AI chat interface
│   │   └── Layout/          # Sidebar and layout
│   ├── services/            # API client and services
│   ├── store/               # Zustand state management
│   ├── hooks/               # Custom React hooks
│   └── lib/                 # Utility functions
├── public/                  # Static assets
└── package.json
```

## Acceptance Criteria (Gates)

- **Gate 1**: Running `npm run dev` shows the dashboard at `localhost:5173`
- **Gate 2**: The "Request Simulator" returns a valid algorithm from the Go backend
- **Gate 3**: Editing YAML in Monaco editor and clicking "Save" updates `configs/policy.yaml` and triggers hot-reload
- **Gate 4**: Typing "Protect IoT devices better" in AI Chat generates valid YAML
- **Gate 5**: The Threat Level gauge changes color when switching policies

## Troubleshooting

### Tailwind CSS not working
Ensure `postcss.config.js` and `tailwind.config.js` are properly configured and that `@tailwind` directives are in `src/index.css`.

### API connection errors
Verify that the Janus Go backend is running on port 8080. Check the browser console for CORS errors.

### Monaco Editor not loading
Monaco Editor requires web workers. If you see errors, try clearing the browser cache or rebuilding the project.

## License

Part of the Janus PQC Engine project.

