import { useEffect } from 'react';
import { ThreatGauge } from './ThreatGauge';
import { StatsCards } from './StatsCards';
import { useAppStore } from '../../store/appStore';
import { janusAPI } from '../../services/janusService';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export function Dashboard() {
  const metrics = useAppStore((state) => state.metrics);
  const setMetrics = useAppStore((state) => state.setMetrics);
  const setLoading = useAppStore((state) => state.setLoading);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setLoading(true);
        const data = await janusAPI.getMetrics();
        setMetrics(data);
      } catch (error) {
        console.error('Failed to fetch metrics:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, [setMetrics, setLoading]);

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading metrics...</div>
      </div>
    );
  }

  const algorithmData = Object.entries(metrics.algorithm_counts).map(([name, count]) => ({
    name,
    count,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Quantum Threat Dashboard</h2>
        <p className="text-gray-600">Real-time monitoring of post-quantum cryptographic decisions</p>
      </div>

      <StatsCards />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatGauge threatLevel={metrics.threat_level} />
        
        <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Algorithm Usage</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={algorithmData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#8b5cf6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
