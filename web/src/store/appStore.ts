import { create } from 'zustand';
import type { AuditVerifyResult, CryptoAsset, Metrics, MigrationPlan, PolicyBundle } from '../services/janusService';

interface AppState {
  currentView: 'dashboard' | 'simulator' | 'policy' | 'ai';
  metrics: Metrics | null;
  policy: string;
  policyBundle: PolicyBundle | null;
  assets: CryptoAsset[];
  migrationPlans: MigrationPlan[];
  auditStatus: AuditVerifyResult | null;
  selectedAssetId: string | null;
  isLoading: boolean;
  error: string | null;
  isDarkMode: boolean;
  
  setCurrentView: (view: 'dashboard' | 'simulator' | 'policy' | 'ai') => void;
  setMetrics: (metrics: Metrics) => void;
  setPolicy: (policy: string) => void;
  setPolicyBundle: (bundle: PolicyBundle | null) => void;
  setAssets: (assets: CryptoAsset[]) => void;
  setMigrationPlans: (plans: MigrationPlan[]) => void;
  setAuditStatus: (status: AuditVerifyResult | null) => void;
  setSelectedAssetId: (assetId: string | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  toggleDarkMode: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  currentView: 'dashboard',
  metrics: null,
  policy: '',
  policyBundle: null,
  assets: [],
  migrationPlans: [],
  auditStatus: null,
  selectedAssetId: null,
  isLoading: false,
  error: null,
  isDarkMode: false,
  
  setCurrentView: (view) => set({ currentView: view }),
  setMetrics: (metrics) => set({ metrics }),
  setPolicy: (policy) => set({ policy }),
  setPolicyBundle: (policyBundle) => set({ policyBundle }),
  setAssets: (assets) => set({ assets }),
  setMigrationPlans: (migrationPlans) => set({ migrationPlans }),
  setAuditStatus: (auditStatus) => set({ auditStatus }),
  setSelectedAssetId: (selectedAssetId) => set({ selectedAssetId }),
  setLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
  toggleDarkMode: () => set((state) => ({ isDarkMode: !state.isDarkMode })),
}));
