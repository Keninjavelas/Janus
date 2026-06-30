// web/src/services/janusService.ts
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

export interface EvaluateRequest {
  scenario: string;
  region: string;            // ✅ MATCHES BACKEND "json:"region""
  risk: number;              // ✅ MATCHES BACKEND "json:"risk""
  device_type?: string;      // ✅ MATCHES BACKEND "json:"device_type""
  key_rotation_hours?: number;
  cert_validity_days?: number;
  latency_budget_ms?: number;
}

export interface AlgorithmConfig {
  kem: string;
  sig: string;
  hybrid_peer: string;
  security_level: number;
}

export interface Metrics {
  total_decisions: number;
  cache_hit_rate: number;
  avg_latency_ms: number;
  p99_latency_ms: number;
  algorithm_counts: Record<string, number>;
  threat_level: 'safe' | 'warning' | 'critical';
}

export const janusAPI = {
  async evaluate(req: EvaluateRequest): Promise<AlgorithmConfig> {
    const response = await axios.post(`${API_BASE}/api/evaluate`, req);
    return response.data;
  },

  async getMetrics(): Promise<Metrics> {
    const response = await axios.get(`${API_BASE}/api/metrics`);
    return response.data;
  },

  async getPolicy(): Promise<string> {
    const response = await axios.get(`${API_BASE}/api/policy`);
    return response.data;
  },

  async updatePolicy(yaml: string): Promise<void> {
    await axios.put(`${API_BASE}/api/policy`, yaml, {
      headers: { 'Content-Type': 'text/yaml' },
    });
  },

  async generateYAML(prompt: string): Promise<string> {
    const response = await axios.post(`${API_BASE}/api/ai/generate`, { prompt });
    return response.data.yaml;
  },
};
