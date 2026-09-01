import { useEffect, useState } from 'react';
import Editor from '@monaco-editor/react';
import { FileCheck2, Loader2, RotateCcw, Save, ShieldAlert } from 'lucide-react';
import toast from 'react-hot-toast';
import { useAppStore } from '../../store/appStore';
import { janusAPI, type PolicyBundle } from '../../services/janusService';

export function YamlEditor() {
  const policy = useAppStore((state) => state.policy);
  const policyBundle = useAppStore((state) => state.policyBundle);
  const setPolicy = useAppStore((state) => state.setPolicy);
  const setPolicyBundle = useAppStore((state) => state.setPolicyBundle);
  const setLoading = useAppStore((state) => state.setLoading);
  const setError = useAppStore((state) => state.setError);
  const [localPolicy, setLocalPolicy] = useState(policy);
  const [isSaving, setIsSaving] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<PolicyBundle | null>(null);

  useEffect(() => {
    const loadPolicy = async () => {
      try {
        setLoading(true);
        const [policyData, bundleData] = await Promise.all([janusAPI.getPolicy(), janusAPI.getPolicyBundle()]);
        setPolicy(policyData);
        setLocalPolicy(policyData);
        setPolicyBundle(bundleData);
        setValidationResult(bundleData);
      } catch (error) {
        setError('Failed to load policy');
        console.error('Failed to load policy:', error);
      } finally {
        setLoading(false);
      }
    };

    void loadPolicy();
  }, [setError, setLoading, setPolicy, setPolicyBundle]);

  const handleValidate = async () => {
    try {
      setIsValidating(true);
      const result = await janusAPI.validatePolicy(localPolicy);
      setValidationResult(result);
      toast.success('Draft policy validated successfully');
    } catch (error: any) {
      const message = error?.response?.data || error?.message || 'Validation failed';
      toast.error(typeof message === 'string' ? message : 'Validation failed');
      console.error('Failed to validate policy:', error);
    } finally {
      setIsValidating(false);
    }
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      const bundle = await janusAPI.updatePolicy(localPolicy);
      setPolicy(localPolicy);
      setPolicyBundle(bundle);
      setValidationResult(bundle);
      toast.success('Policy activated and reloaded successfully');
    } catch (error: any) {
      const message = error?.response?.data || error?.message || 'Failed to save policy';
      toast.error(typeof message === 'string' ? message : 'Failed to save policy');
      console.error('Failed to save policy:', error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    setLocalPolicy(policy);
    setValidationResult(policyBundle);
    toast.success('Editor reset to the loaded policy');
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-stone-900">Policy Lifecycle</h2>
        <p className="mt-2 text-sm leading-6 text-stone-600">
          Draft with the AI copilot if needed, validate here, then activate manually. Janus does not auto-apply LLM output.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="overflow-hidden rounded-2xl border border-stone-200 bg-white shadow-sm">
          <div className="flex items-center justify-between border-b border-stone-200 bg-stone-50 p-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-stone-500">configs/policy.yaml</p>
              <p className="mt-1 text-sm text-stone-600">Validate before activate. Unknown algorithms and invalid ranges are rejected.</p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleReset}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-stone-700 transition-colors hover:bg-stone-200"
              >
                <RotateCcw className="h-4 w-4" />
                Reset
              </button>
              <button
                onClick={handleValidate}
                disabled={isValidating}
                className="flex items-center gap-2 rounded-lg bg-stone-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-stone-800 disabled:opacity-50"
              >
                {isValidating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileCheck2 className="h-4 w-4" />}
                {isValidating ? 'Validating...' : 'Validate Draft'}
              </button>
              <button
                onClick={handleSave}
                disabled={isSaving}
                className="flex items-center gap-2 rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-orange-500 disabled:opacity-50"
              >
                {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {isSaving ? 'Activating...' : 'Activate Policy'}
              </button>
            </div>
          </div>

          <div className="h-[640px]">
            <Editor
              height="100%"
              defaultLanguage="yaml"
              value={localPolicy}
              onChange={(value) => setLocalPolicy(value || '')}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true,
              }}
            />
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl border border-stone-200 bg-white p-5 shadow-sm">
            <div className="flex items-center gap-3">
              <ShieldAlert className="h-5 w-5 text-orange-600" />
              <div>
                <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">AI Safety</p>
                <h3 className="text-lg font-semibold text-stone-900">Draft-only copilot</h3>
              </div>
            </div>
            <p className="mt-3 text-sm leading-6 text-stone-600">
              Natural language becomes a candidate policy only. Janus requires schema validation, semantic validation, invariant checks, and manual activation.
            </p>
          </div>

          <div className="rounded-2xl border border-stone-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-stone-500">Policy Bundle</p>
            {validationResult ? (
              <div className="mt-4 space-y-3 text-sm text-stone-700">
                <div className="rounded-xl bg-stone-50 p-3">
                  <p className="text-xs uppercase tracking-wide text-stone-500">State</p>
                  <p className="mt-2 font-semibold text-stone-900">{validationResult.state}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-3">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Policy ID</p>
                  <p className="mt-2 break-all font-mono text-xs text-stone-800">{validationResult.policy_id}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-3">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Version</p>
                  <p className="mt-2 break-all font-mono text-xs text-stone-800">{validationResult.version}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-3">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Canonical hash</p>
                  <p className="mt-2 break-all font-mono text-xs text-stone-800">{validationResult.canonical_hash}</p>
                </div>
                <div className="rounded-xl bg-stone-50 p-3">
                  <p className="text-xs uppercase tracking-wide text-stone-500">Signature</p>
                  <p className="mt-2 text-sm text-stone-700">
                    {validationResult.signature
                      ? `${validationResult.signature.algorithm} by ${validationResult.signature.signer}`
                      : 'No signature metadata for this draft'}
                  </p>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-sm text-stone-500">Validate a draft to inspect its canonical bundle metadata.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
