import { useEffect, useMemo, useState, startTransition } from 'react';
import { ShieldCheck, ShieldX, Waypoints, FileBadge2 } from 'lucide-react';
import { StatsCards } from './StatsCards';
import { ThreatGauge } from './ThreatGauge';
import { useAppStore } from '../../store/appStore';
import { janusAPI, type CryptoAsset, type MigrationPlan } from '../../services/janusService';

function formatDate(value?: string) {
  if (!value) {
    return 'Not observed';
  }
  return new Date(value).toLocaleString();
}

function statusTone(status?: string) {
  switch (status) {
    case 'COMPLIANT':
    case 'ATTRIBUTED':
    case 'VERIFIED':
      return 'bg-emerald-100 text-emerald-800';
    case 'NON_COMPLIANT':
    case 'AMBIGUOUS':
    case 'BLOCKED':
    case 'NOT_VERIFIED':
      return 'bg-rose-100 text-rose-800';
    case 'UNVERIFIED':
    case 'UNATTRIBUTED':
    case 'PENDING':
      return 'bg-amber-100 text-amber-800';
    default:
      return 'bg-stone-100 text-stone-700';
  }
}

function lookupPlan(asset: CryptoAsset, plans: MigrationPlan[]) {
  return plans.find((plan) => plan.asset_id === asset.id) ?? null;
}

export function Dashboard() {
  const metrics = useAppStore((state) => state.metrics);
  const assets = useAppStore((state) => state.assets);
  const migrationPlans = useAppStore((state) => state.migrationPlans);
  const auditStatus = useAppStore((state) => state.auditStatus);
  const selectedAssetId = useAppStore((state) => state.selectedAssetId);
  const setMetrics = useAppStore((state) => state.setMetrics);
  const setAssets = useAppStore((state) => state.setAssets);
  const setMigrationPlans = useAppStore((state) => state.setMigrationPlans);
  const setAuditStatus = useAppStore((state) => state.setAuditStatus);
  const setSelectedAssetId = useAppStore((state) => state.setSelectedAssetId);
  const setLoading = useAppStore((state) => state.setLoading);
  const setError = useAppStore((state) => state.setError);
  const [planningAssetId, setPlanningAssetId] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const refresh = async () => {
      try {
        setLoading(true);
        const [metricsData, assetData, planData, auditData] = await Promise.all([
          janusAPI.getMetrics(),
          janusAPI.getAssets(),
          janusAPI.getMigrationPlans(),
          janusAPI.verifyAudit(),
        ]);

        if (!mounted) {
          return;
        }

        startTransition(() => {
          setMetrics(metricsData);
          setAssets(assetData);
          setMigrationPlans(planData);
          setAuditStatus(auditData);
          if (!selectedAssetId && assetData.length > 0) {
            setSelectedAssetId(assetData[0].id);
          }
        });
      } catch (error) {
        console.error('Failed to refresh dashboard', error);
        setError('Failed to refresh quantum readiness data');
      } finally {
        setLoading(false);
      }
    };

    void refresh();
    const interval = setInterval(refresh, 8000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [selectedAssetId, setAssets, setAuditStatus, setError, setLoading, setMetrics, setMigrationPlans, setSelectedAssetId]);

  const selectedAsset = useMemo(() => {
    if (assets.length === 0) {
      return null;
    }
    return assets.find((asset) => asset.id === selectedAssetId) ?? assets[0];
  }, [assets, selectedAssetId]);

  const selectedPlan = selectedAsset ? lookupPlan(selectedAsset, migrationPlans) : null;

  const handleBuildPlan = async (asset: CryptoAsset) => {
    try {
      setPlanningAssetId(asset.id);
      const plan = await janusAPI.buildMigrationPlan({
        asset_id: asset.id,
        mode: asset.quantum_safe ? 'AUDIT' : 'ENFORCE',
        data_sensitivity: asset.quantum_safe ? 'confidential' : 'restricted',
        confidentiality_years: asset.quantum_safe ? 10 : 30,
        asset_criticality: asset.quantum_safe ? 'important' : 'critical',
        external_exposure: asset.port === 443 || asset.port === 8443,
        migration_ready: !asset.stale,
        compatibility_blockers: asset.key_exchange === 'UNKNOWN' ? ['Unknown algorithm requires manual validation'] : [],
      });
      setMigrationPlans([...migrationPlans.filter((existing) => existing.asset_id !== plan.asset_id), plan]);
    } catch (error) {
      console.error('Failed to build migration plan', error);
      setError('Failed to build migration plan');
    } finally {
      setPlanningAssetId(null);
    }
  };

  if (!metrics) {
    return <div className="rounded-2xl border border-stone-200 bg-white p-8 text-stone-600 shadow-sm">Loading Janus quantum readiness data...</div>;
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-stone-200 bg-gradient-to-br from-stone-950 via-stone-900 to-orange-900 p-8 text-white shadow-xl">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.28em] text-orange-200">Janus v1.0 Research Release</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Evidence-backed quantum migration posture</h2>
            <p className="mt-3 text-sm leading-7 text-stone-300">
              Janus now correlates passive wire evidence, workload attribution, discovery inventory, explainable quantum risk,
              and migration planning without collapsing those security facts into each other.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p className="text-stone-400">Audit chain</p>
              <p className="mt-2 text-lg font-semibold">{auditStatus?.valid ? 'Verified' : 'Attention required'}</p>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p className="text-stone-400">Active assets</p>
              <p className="mt-2 text-lg font-semibold">{metrics.total_assets}</p>
            </div>
          </div>
        </div>
      </section>

      <StatsCards metrics={metrics} />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <ThreatGauge
          exposureLevel={metrics.quantum_exposure}
          classicalAssets={metrics.classical_assets}
          quantumSafeAssets={metrics.quantum_safe_assets}
          unknownAssets={metrics.unknown_assets}
        />

        <div className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Control Plane Health</p>
              <h3 className="mt-1 text-xl font-semibold text-stone-900">Research release status</h3>
            </div>
            {auditStatus?.valid ? <ShieldCheck className="h-8 w-8 text-emerald-600" /> : <ShieldX className="h-8 w-8 text-rose-600" />}
          </div>

          <div className="mt-5 space-y-4">
            <div className="rounded-xl bg-stone-50 p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-stone-600">Tamper-evident audit chain</span>
                <span className={`rounded-full px-3 py-1 text-xs font-semibold ${auditStatus?.valid ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}`}>
                  {auditStatus?.valid ? 'VALID' : 'INVALID'}
                </span>
              </div>
              <p className="mt-2 text-sm text-stone-500">
                {auditStatus?.valid
                  ? `${auditStatus.records} audit records verified`
                  : auditStatus?.failure_reason || 'Audit verification has not completed'}
              </p>
            </div>

            <div className="rounded-xl bg-stone-50 p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-stone-600">Observed migration backlog</span>
                <Waypoints className="h-5 w-5 text-orange-600" />
              </div>
              <p className="mt-2 text-sm text-stone-500">
                {metrics.migration_priority_counts.P0 + metrics.migration_priority_counts.P1} high-priority plans and {metrics.migration_priority_counts.P2 + metrics.migration_priority_counts.P3} lower-priority plans are currently visible in the control plane.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <section className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Discovery Inventory</p>
              <h3 className="mt-1 text-xl font-semibold text-stone-900">Observed cryptographic assets</h3>
            </div>
            <span className="rounded-full bg-stone-100 px-3 py-1 text-xs font-semibold text-stone-600">{assets.length} assets</span>
          </div>

          <div className="overflow-hidden rounded-2xl border border-stone-200">
            <table className="min-w-full divide-y divide-stone-200 text-sm">
              <thead className="bg-stone-50 text-left text-stone-500">
                <tr>
                  <th className="px-4 py-3 font-medium">Service</th>
                  <th className="px-4 py-3 font-medium">Observed</th>
                  <th className="px-4 py-3 font-medium">Crypto</th>
                  <th className="px-4 py-3 font-medium">Ownership</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-100 bg-white">
                {assets.map((asset) => (
                  <tr
                    key={asset.id}
                    onClick={() => setSelectedAssetId(asset.id)}
                    className={`cursor-pointer transition-colors hover:bg-orange-50 ${selectedAsset?.id === asset.id ? 'bg-orange-50/80' : ''}`}
                  >
                    <td className="px-4 py-3">
                      <p className="font-medium text-stone-900">{asset.host}:{asset.port}</p>
                      <p className="text-xs text-stone-500">{asset.evidence_source}</p>
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-stone-900">{asset.key_exchange || 'UNKNOWN'}</p>
                      <p className="text-xs text-stone-500">{asset.tls_version || 'TLS unknown'}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusTone(asset.crypto_status)}`}>
                        {asset.crypto_status || 'UNKNOWN'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusTone(asset.attribution_status)}`}>
                        {asset.attribution_status || 'UNKNOWN'}
                      </span>
                    </td>
                  </tr>
                ))}
                {assets.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-stone-500">
                      No discovery evidence has been ingested yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Workload Detail</p>
              <h3 className="mt-1 text-xl font-semibold text-stone-900">Selected connection evidence</h3>
            </div>
            <FileBadge2 className="h-6 w-6 text-stone-400" />
          </div>

          {!selectedAsset ? (
            <p className="text-sm text-stone-500">Select a discovered asset to inspect its workload, cryptography, and migration state.</p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl bg-stone-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Required posture</p>
                  <p className="mt-2 text-lg font-semibold text-stone-900">{selectedAsset.required_posture || 'Not set'}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Observed posture</p>
                  <p className="mt-2 text-lg font-semibold text-stone-900">{selectedAsset.key_exchange || 'UNKNOWN'}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Crypto verdict</p>
                  <span className={`mt-2 inline-flex rounded-full px-3 py-1 text-xs font-semibold ${statusTone(selectedAsset.crypto_status)}`}>
                    {selectedAsset.crypto_status || 'UNKNOWN'}
                  </span>
                </div>
                <div className="rounded-xl bg-stone-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Attribution verdict</p>
                  <span className={`mt-2 inline-flex rounded-full px-3 py-1 text-xs font-semibold ${statusTone(selectedAsset.attribution_status)}`}>
                    {selectedAsset.attribution_status || 'UNKNOWN'}
                  </span>
                </div>
              </div>

              <div className="rounded-xl border border-stone-200 p-4">
                <p className="text-xs uppercase tracking-wide text-stone-500">Owning workload</p>
                {selectedAsset.workload ? (
                  <div className="mt-3 space-y-2 text-sm text-stone-700">
                    <p><span className="font-semibold text-stone-900">PID:</span> {selectedAsset.workload.pid}</p>
                    <p><span className="font-semibold text-stone-900">Executable:</span> {selectedAsset.workload.executable}</p>
                    <p><span className="font-semibold text-stone-900">Process start:</span> {selectedAsset.workload.process_start_time_ticks}</p>
                    <p><span className="font-semibold text-stone-900">Socket inode:</span> {selectedAsset.workload.socket_inode}</p>
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-stone-500">No owning workload could be established for this observation.</p>
                )}
              </div>

              <div className="rounded-xl border border-stone-200 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-stone-500">Migration view</p>
                    <p className="mt-1 text-sm text-stone-600">Plan against real wire evidence rather than configuration intent.</p>
                  </div>
                  <button
                    onClick={() => void handleBuildPlan(selectedAsset)}
                    disabled={planningAssetId === selectedAsset.id}
                    className="rounded-lg bg-stone-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-stone-800 disabled:opacity-50"
                  >
                    {planningAssetId === selectedAsset.id ? 'Planning...' : selectedPlan ? 'Refresh Plan' : 'Plan Migration'}
                  </button>
                </div>

                {selectedPlan ? (
                  <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                    <div className="rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Target</p>
                      <p className="mt-2 font-semibold text-stone-900">{selectedPlan.target}</p>
                    </div>
                    <div className="rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Verification</p>
                      <span className={`mt-2 inline-flex rounded-full px-2 py-1 text-xs font-semibold ${statusTone(selectedPlan.verification_state)}`}>
                        {selectedPlan.verification_state}
                      </span>
                    </div>
                    <div className="rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Risk / Priority</p>
                      <p className="mt-2 font-semibold text-stone-900">{selectedPlan.risk} / {selectedPlan.priority}</p>
                    </div>
                    <div className="rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Plan status</p>
                      <span className={`mt-2 inline-flex rounded-full px-2 py-1 text-xs font-semibold ${statusTone(selectedPlan.status)}`}>
                        {selectedPlan.status}
                      </span>
                    </div>
                    <div className="col-span-2 rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Reasons</p>
                      <p className="mt-2 text-sm text-stone-700">{selectedPlan.reasons?.join(', ') || 'No reasons recorded yet.'}</p>
                    </div>
                    <div className="col-span-2 rounded-xl bg-stone-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-stone-500">Blockers</p>
                      <p className="mt-2 text-sm text-stone-700">{selectedPlan.blockers?.length ? selectedPlan.blockers.join(', ') : 'No blockers recorded.'}</p>
                    </div>
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-stone-500">No migration plan exists yet for this asset.</p>
                )}
              </div>

              <p className="text-xs text-stone-500">First seen {formatDate(selectedAsset.first_seen)}. Last seen {formatDate(selectedAsset.last_seen)}.</p>
            </div>
          )}
        </section>
      </div>

      <section className="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Migration Planner</p>
            <h3 className="mt-1 text-xl font-semibold text-stone-900">Evidence-backed migration backlog</h3>
          </div>
        </div>

        <div className="overflow-hidden rounded-2xl border border-stone-200">
          <table className="min-w-full divide-y divide-stone-200 text-sm">
            <thead className="bg-stone-50 text-left text-stone-500">
              <tr>
                <th className="px-4 py-3 font-medium">Asset</th>
                <th className="px-4 py-3 font-medium">Current</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Priority</th>
                <th className="px-4 py-3 font-medium">Verification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-stone-100">
              {migrationPlans.map((plan) => (
                <tr key={plan.asset_id}>
                  <td className="px-4 py-3 font-medium text-stone-900">{plan.asset_id}</td>
                  <td className="px-4 py-3 text-stone-700">{plan.current}</td>
                  <td className="px-4 py-3 text-stone-700">{plan.target}</td>
                  <td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusTone(plan.priority)}`}>{plan.priority}</span></td>
                  <td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusTone(plan.verification_state)}`}>{plan.verification_state}</span></td>
                </tr>
              ))}
              {migrationPlans.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-stone-500">
                    No migration plans have been created yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
