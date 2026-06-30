import { useEffect, useState } from 'react';
import Editor from '@monaco-editor/react';
import { Save, RotateCcw, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';
import { useAppStore } from '../../store/appStore';
import { janusAPI } from '../../services/janusService';

export function YamlEditor() {
  const policy = useAppStore((state) => state.policy);
  const setPolicy = useAppStore((state) => state.setPolicy);
  const setLoading = useAppStore((state) => state.setLoading);
  const setError = useAppStore((state) => state.setError);
  const [localPolicy, setLocalPolicy] = useState(policy);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    const loadPolicy = async () => {
      try {
        setLoading(true);
        const data = await janusAPI.getPolicy();
        setPolicy(data);
        setLocalPolicy(data);
      } catch (error) {
        setError('Failed to load policy');
        console.error('Failed to load policy:', error);
      } finally {
        setLoading(false);
      }
    };

    loadPolicy();
  }, [setPolicy, setLoading, setError]);

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await janusAPI.updatePolicy(localPolicy);
      setPolicy(localPolicy);
      toast.success('Policy saved and hot-reloaded successfully!');
    } catch (error) {
      toast.error('Failed to save policy');
      console.error('Failed to save policy:', error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    setLocalPolicy(policy);
    toast('Changes reverted.', { icon: '🔄' });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Policy Editor</h2>
        <p className="text-gray-600">Edit and hot-reload cryptographic policies</p>
      </div>

      <div className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 bg-gray-50">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-700">configs/policy.yaml</span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleReset}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </button>
            <button
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-purple-400 transition-colors"
            >
              {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              {isSaving ? 'Saving...' : 'Save & Reload'}
            </button>
          </div>
        </div>

        <div className="h-[600px]">
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
    </div>
  );
}
