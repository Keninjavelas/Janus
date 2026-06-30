import { create } from 'zustand';
import type { Metrics } from '../services/janusService';

interface AppState {
  currentView: 'dashboard' | 'simulator' | 'policy' | 'ai';
  metrics: Metrics | null;
  policy: string;
  isLoading: boolean;
  error: string | null;
  isDarkMode: boolean;
  
  setCurrentView: (view: 'dashboard' | 'simulator' | 'policy' | 'ai') => void;
  setMetrics: (metrics: Metrics) => void;
  setPolicy: (policy: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  toggleDarkMode: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  currentView: 'dashboard',
  metrics: null,
  policy: '',
  isLoading: false,
  error: null,
  isDarkMode: false,
  
  setCurrentView: (view) => set({ currentView: view }),
  setMetrics: (metrics) => set({ metrics }),
  setPolicy: (policy) => set({ policy }),
  setLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
  toggleDarkMode: () => set((state) => ({ isDarkMode: !state.isDarkMode })),
}));
