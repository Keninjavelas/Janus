import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface ThreatGaugeProps {
  threatLevel: 'safe' | 'warning' | 'critical';
}

export function ThreatGauge({ threatLevel }: ThreatGaugeProps) {
  const getThreatInfo = () => {
    switch (threatLevel) {
      case 'safe':
        return {
          color: 'bg-green-500',
          textColor: 'text-green-600',
          icon: CheckCircle,
          label: 'Safe',
          description: 'All systems operating with quantum-safe algorithms',
        };
      case 'warning':
        return {
          color: 'bg-yellow-500',
          textColor: 'text-yellow-600',
          icon: AlertTriangle,
          label: 'Warning',
          description: 'Some systems using lower security levels',
        };
      case 'critical':
        return {
          color: 'bg-red-500',
          textColor: 'text-red-600',
          icon: Shield,
          label: 'Critical',
          description: 'Classical algorithms detected - upgrade required',
        };
    }
  };

  const threatInfo = getThreatInfo();
  const Icon = threatInfo.icon;

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-200">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Quantum Threat Level</h3>
        <Icon className={`w-6 h-6 ${threatInfo.textColor}`} />
      </div>
      
      <div className="flex items-center gap-6">
        <div className={`w-32 h-32 rounded-full ${threatInfo.color} flex items-center justify-center shadow-lg`}>
          <span className="text-white text-2xl font-bold">{threatInfo.label}</span>
        </div>
        
        <div className="flex-1">
          <p className="text-gray-600 mb-2">{threatInfo.description}</p>
          <div className="flex gap-2">
            <div className={`h-2 flex-1 rounded-full ${threatLevel === 'safe' ? threatInfo.color : 'bg-gray-200'}`} />
            <div className={`h-2 flex-1 rounded-full ${threatLevel === 'warning' || threatLevel === 'safe' ? threatInfo.color : 'bg-gray-200'}`} />
            <div className={`h-2 flex-1 rounded-full ${threatLevel === 'critical' ? threatInfo.color : 'bg-gray-200'}`} />
          </div>
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>Safe</span>
            <span>Warning</span>
            <span>Critical</span>
          </div>
        </div>
      </div>
    </div>
  );
}
