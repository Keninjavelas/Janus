import type { Metrics } from '../../services/janusService';

interface StatsCardsProps {
  metrics: Metrics;
}

export function StatsCards({ metrics }: StatsCardsProps) {
  const cards = [
    { label: 'Decisions', value: metrics.total_decisions.toLocaleString(), tone: 'text-stone-900' },
    { label: 'Assets', value: metrics.total_assets.toLocaleString(), tone: 'text-stone-900' },
    { label: 'Cache Hit Rate', value: `${(metrics.cache_hit_rate * 100).toFixed(1)}%`, tone: 'text-sky-700' },
    { label: 'P99 Latency', value: `${metrics.p99_latency_ms.toFixed(2)} ms`, tone: 'text-amber-700' },
    { label: 'P0', value: String(metrics.migration_priority_counts.P0 ?? 0), tone: 'text-rose-700' },
    { label: 'P1', value: String(metrics.migration_priority_counts.P1 ?? 0), tone: 'text-orange-700' },
    { label: 'P2', value: String(metrics.migration_priority_counts.P2 ?? 0), tone: 'text-sky-700' },
    { label: 'P3', value: String(metrics.migration_priority_counts.P3 ?? 0), tone: 'text-emerald-700' },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
      {cards.map((card) => (
        <div key={card.label} className="rounded-2xl border border-stone-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-stone-500">{card.label}</p>
          <p className={`mt-3 text-3xl font-semibold ${card.tone}`}>{card.value}</p>
        </div>
      ))}
    </div>
  );
}
