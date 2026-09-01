import { AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';

interface ThreatGaugeProps {
  exposureLevel: 'safe' | 'warning' | 'critical';
  classicalAssets: number;
  quantumSafeAssets: number;
  unknownAssets: number;
}

export function ThreatGauge({ exposureLevel, classicalAssets, quantumSafeAssets, unknownAssets }: ThreatGaugeProps) {
  const info = (() => {
    switch (exposureLevel) {
      case 'safe':
        return {
          color: 'bg-emerald-500',
          textColor: 'text-emerald-700',
          icon: CheckCircle,
          label: 'Low Exposure',
          description: 'Observed assets are predominantly quantum-safe and migration urgency is low.',
        };
      case 'warning':
        return {
          color: 'bg-amber-500',
          textColor: 'text-amber-700',
          icon: AlertTriangle,
          label: 'Mixed Exposure',
          description: 'Unknown or transitional assets remain and should be prioritized for assessment.',
        };
      default:
        return {
          color: 'bg-rose-600',
          textColor: 'text-rose-700',
          icon: ShieldAlert,
          label: 'High Exposure',
          description: 'Classical or high-priority assets remain in scope for migration and verification.',
        };
    }
  })();

  const Icon = info.icon;

  return (
    <div className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Quantum Exposure</p>
          <h3 className="mt-1 text-xl font-semibold text-stone-900">{info.label}</h3>
        </div>
        <div className={`rounded-full p-3 ${info.color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>

      <p className="mb-6 text-sm leading-6 text-stone-600">{info.description}</p>

      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl bg-stone-50 p-3">
          <p className="text-xs uppercase tracking-wide text-stone-500">Quantum-safe</p>
          <p className="mt-2 text-2xl font-semibold text-emerald-700">{quantumSafeAssets}</p>
        </div>
        <div className="rounded-xl bg-stone-50 p-3">
          <p className="text-xs uppercase tracking-wide text-stone-500">Classical</p>
          <p className="mt-2 text-2xl font-semibold text-rose-700">{classicalAssets}</p>
        </div>
        <div className="rounded-xl bg-stone-50 p-3">
          <p className="text-xs uppercase tracking-wide text-stone-500">Unknown</p>
          <p className="mt-2 text-2xl font-semibold text-amber-700">{unknownAssets}</p>
        </div>
      </div>
    </div>
  );
}
