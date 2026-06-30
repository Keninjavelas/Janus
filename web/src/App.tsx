import { Sidebar } from './components/Layout/Sidebar';
import { Dashboard } from './components/Dashboard/Dashboard';
import { RequestForm } from './components/Simulator/RequestForm';
import { YamlEditor } from './components/PolicyEditor/YamlEditor';
import { ChatInterface } from './components/AICopilot/ChatInterface';
import { useAppStore } from './store/appStore';
import { Toaster } from 'react-hot-toast';

function App() {
  const currentView = useAppStore((state) => state.currentView);
  const isDarkMode = useAppStore((state) => state.isDarkMode);

  const renderView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard />;
      case 'simulator':
        return <RequestForm />;
      case 'policy':
        return <YamlEditor />;
      case 'ai':
        return <ChatInterface />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className={isDarkMode ? 'dark' : ''}>
      <div className="flex min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
        <Toaster position="top-right" />
        <Sidebar />
        <main className="flex-1 p-8 overflow-auto">
          {renderView()}
        </main>
      </div>
    </div>
  );
}

export default App;
