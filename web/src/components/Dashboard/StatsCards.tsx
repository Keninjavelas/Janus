// web/src/components/Dashboard/StatsCards.tsx
import React, { useEffect, useState } from 'react';
import { janusAPI, type Metrics } from '../../services/janusService';

export const StatsCards: React.FC = () => {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    try {
      const data = await janusAPI.getMetrics();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to fetch metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="text-center py-4">Loading metrics...</div>;
  }

  if (!metrics) {
    return <div className="text-center py-4 text-red-500">Failed to load metrics</div>;
  }

  const cards = [
    { label: 'Total Decisions', value: metrics.total_decisions.toLocaleString() },
    { label: 'Cache Hit Rate', value: `${(metrics.cache_hit_rate * 100).toFixed(1)}%` },
    { label: 'Avg Latency', value: `${metrics.avg_latency_ms.toFixed(2)}ms` },
    { label: 'P99 Latency', value: `${metrics.p99_latency_ms.toFixed(2)}ms` },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => (
        <div key={idx} className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">{card.label}</p>
          <p className="text-2xl font-bold">{card.value}</p>
        </div>
      ))}
    </div>
  );
};
