// web/src/components/Simulator/RequestForm.tsx
import React, { useState } from 'react';
import { janusAPI, type EvaluateRequest, type AlgorithmConfig } from '../../services/janusService';

export const RequestForm: React.FC = () => {
  const [scenario, setScenario] = useState('SERVICE_MESH');
  const [region, setRegion] = useState('US');
  const [risk, setRisk] = useState(3);
  const [deviceType, setDeviceType] = useState('');
  const [keyRotationHours, setKeyRotationHours] = useState(24);
  const [certValidityDays, setCertValidityDays] = useState(30);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AlgorithmConfig | null>(null);
  const [latency, setLatency] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    setLatency(null);

    const payload: EvaluateRequest = {
      scenario,
      region,
      risk,
    };

    if (deviceType) payload.device_type = deviceType;
    if (keyRotationHours) payload.key_rotation_hours = keyRotationHours;
    if (certValidityDays) payload.cert_validity_days = certValidityDays;

    const start = performance.now();
    try {
      const data = await janusAPI.evaluate(payload);
      const end = performance.now();
      setResult(data);
      setLatency(end - start);
    } catch (err: any) {
      setError(err.message || 'Failed to evaluate');
    } finally {
      setLoading(false);
    }
  };

  const getSecurityColor = (level: number) => {
    if (level >= 5) return 'text-red-600 bg-red-100';
    if (level >= 3) return 'text-yellow-600 bg-yellow-100';
    return 'text-green-600 bg-green-100';
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-4">Request Simulator</h2>
      <p className="text-gray-500 dark:text-gray-400 mb-6">
        Test cryptographic decisions with different scenarios
      </p>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Scenario */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Scenario</label>
          <select
            value={scenario}
            onChange={(e) => setScenario(e.target.value)}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="SERVICE_MESH">SERVICE MESH</option>
            <option value="MICROSEGMENTATION">MICROSEGMENTATION</option>
            <option value="IOT_EDGE">IOT EDGE</option>
            <option value="API_GATEWAY">API GATEWAY</option>
            <option value="ROOT_CA">ROOT CA</option>
            <option value="REMOTE_ACCESS">REMOTE ACCESS</option>
          </select>
        </div>

        {/* Region */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Region</label>
          <select
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="US">🇺🇸 US</option>
            <option value="EU">🇪🇺 EU</option>
            <option value="APAC">🌏 APAC</option>
          </select>
        </div>

        {/* Risk Slider */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Risk Level: {risk}
          </label>
          <input
            type="range"
            min="1"
            max="5"
            step="1"
            value={risk}
            onChange={(e) => setRisk(parseInt(e.target.value))}
            className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700"
          />
          <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
            <span>Low</span>
            <span>High</span>
          </div>
        </div>

        {/* Advanced Options Toggle */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-sm text-indigo-600 hover:text-indigo-800 dark:text-indigo-400"
        >
          {showAdvanced ? '▼ Hide Advanced Options' : '▶ Show Advanced Options'}
        </button>

        {showAdvanced && (
          <div className="space-y-4 p-4 border border-gray-200 dark:border-gray-700 rounded-md">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Device Type</label>
              <select
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600"
              >
                <option value="">None</option>
                <option value="server">Server</option>
                <option value="iot">IoT</option>
                <option value="mobile">Mobile</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Key Rotation (hours)
              </label>
              <input
                type="number"
                value={keyRotationHours}
                onChange={(e) => setKeyRotationHours(parseInt(e.target.value) || 0)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Cert Validity (days)
              </label>
              <input
                type="number"
                value={certValidityDays}
                onChange={(e) => setCertValidityDays(parseInt(e.target.value) || 0)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600"
              />
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded-md disabled:opacity-50 transition-colors"
        >
          {loading ? '⏳ Testing...' : '🔒 Test Connection'}
        </button>
      </form>

      {/* Results */}
      {error && (
        <div className="mt-6 p-4 bg-red-100 text-red-700 rounded-md">
          ❌ Error: {error}
        </div>
      )}

      {result && (
        <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-md">
          <h3 className="font-semibold text-lg mb-2">Recommendation</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-sm text-gray-500 dark:text-gray-400">KEM</span>
              <p className="font-mono text-lg font-bold text-indigo-600 dark:text-indigo-400">{result.kem}</p>
            </div>
            <div>
              <span className="text-sm text-gray-500 dark:text-gray-400">Signature</span>
              <p className="font-mono text-lg">{result.sig || 'None'}</p>
            </div>
            <div>
              <span className="text-sm text-gray-500 dark:text-gray-400">Security Level</span>
              <p className={`font-mono text-lg font-bold px-2 py-1 rounded inline-block ${getSecurityColor(result.security_level)}`}>
                {result.security_level}
              </p>
            </div>
            <div>
              <span className="text-sm text-gray-500 dark:text-gray-400">Latency</span>
              <p className="font-mono text-lg">{latency?.toFixed(2)} ms</p>
            </div>
          </div>
          {result.hybrid_peer && (
            <div className="mt-2 text-sm text-gray-500">
              Hybrid Peer: {result.hybrid_peer}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
