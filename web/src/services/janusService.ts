import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

export interface EvaluateRequest {
  scenario: string;
  region: string;
  risk: number;
  device_type?: string;
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
  quantum_exposure: 'safe' | 'warning' | 'critical';
  total_assets: number;
  quantum_safe_assets: number;
  classical_assets: number;
  unknown_assets: number;
  migration_priority_counts: Record<'P0' | 'P1' | 'P2' | 'P3', number>;
}

export interface WorkloadMetadata {
  pid: number;
  executable: string;
  process_start_time_ticks?: number;
  socket_inode?: string;
}

export interface CryptoAsset {
  id: string;
  host: string;
  port: number;
  protocol: string;
  tls_version?: string;
  key_exchange?: string;
  key_exchange_class: 'CLASSICAL' | 'HYBRID_PQ' | 'UNKNOWN';
  quantum_safe: boolean;
  signature?: string;
  required_posture?: string;
  crypto_status?: string;
  attribution_status?: string;
  workload?: WorkloadMetadata;
  evidence_source: string;
  first_seen: string;
  last_seen: string;
  stale?: boolean;
}

export interface CBOM {
  generated_at: string;
  assets: CryptoAsset[];
}

export interface RiskAssessment {
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  reasons: string[];
  score: number;
}

export interface MigrationPlan {
  asset_id: string;
  service: string;
  current: string;
  target: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  status: 'NOT_STARTED' | 'PLANNED' | 'CANARY' | 'MIGRATING' | 'VERIFIED' | 'BLOCKED' | 'ROLLED_BACK';
  mode: 'AUDIT' | 'WARN' | 'ENFORCE';
  blockers?: string[];
  reasons?: string[];
  verification_state: 'PENDING' | 'VERIFIED' | 'NOT_VERIFIED';
  last_verified_at?: string;
  last_verification_id?: string;
}

export interface AuditVerifyResult {
  valid: boolean;
  records: number;
  failure_reason?: string;
}

export interface PolicyBundle {
  policy: unknown;
  version: string;
  policy_id: string;
  canonical_hash: string;
  active: boolean;
  state: string;
  created_at: string;
  signature?: {
    algorithm: string;
    signer: string;
    value: string;
    signed_at: string;
  };
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

  async getPolicyBundle(): Promise<PolicyBundle> {
    const response = await axios.get(`${API_BASE}/api/policy/bundle`);
    return response.data;
  },

  async validatePolicy(yaml: string): Promise<PolicyBundle> {
    const response = await axios.post(`${API_BASE}/api/policy/validate`, yaml, {
      headers: { 'Content-Type': 'text/yaml' },
    });
    return response.data;
  },

  async updatePolicy(yaml: string): Promise<PolicyBundle> {
    const response = await axios.put(`${API_BASE}/api/policy`, yaml, {
      headers: { 'Content-Type': 'text/yaml' },
    });
    return response.data;
  },

  async generateYAML(prompt: string): Promise<string> {
    const response = await axios.post(`${API_BASE}/api/ai/generate`, { prompt });
    return response.data.yaml;
  },

  async getAssets(): Promise<CryptoAsset[]> {
    const response = await axios.get(`${API_BASE}/api/discovery/assets`);
    return response.data;
  },

  async getCBOM(): Promise<CBOM> {
    const response = await axios.get(`${API_BASE}/api/discovery/cbom`);
    return response.data;
  },

  async evaluateRisk(payload: Record<string, unknown>): Promise<RiskAssessment> {
    const response = await axios.post(`${API_BASE}/api/risk/evaluate`, payload);
    return response.data;
  },

  async getMigrationPlans(): Promise<MigrationPlan[]> {
    const response = await axios.get(`${API_BASE}/api/migration/plans`);
    return response.data;
  },

  async buildMigrationPlan(payload: Record<string, unknown>): Promise<MigrationPlan> {
    const response = await axios.post(`${API_BASE}/api/migration/plan`, payload);
    return response.data;
  },

  async verifyAudit(): Promise<AuditVerifyResult> {
    const response = await axios.get(`${API_BASE}/api/audit/verify`);
    return response.data;
  },
};
