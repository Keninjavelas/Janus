import { useState } from 'react';
import { Send, Bot, User, Sparkles } from 'lucide-react';
import { janusAPI } from '../../services/janusService';
import { useAppStore } from '../../store/appStore';
import toast from 'react-hot-toast';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        'Hello. I am the Janus Policy Assistant. Describe the posture you want, and I will draft YAML for review in the Policy Editor. Example: "Protect EU traffic more strictly" or "Require stronger posture for high-risk IoT traffic".',
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const setPolicy = useAppStore((state) => state.setPolicy);
  const setCurrentView = useAppStore((state) => state.setCurrentView);
  const setLoading = useAppStore((state) => state.setLoading);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage: Message = { role: 'user', content: input };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const yaml = await janusAPI.generateYAML(input);

      const assistantMessage: Message = {
        role: 'assistant',
        content: `I drafted the following YAML based on your request:\n\n\`\`\`yaml\n${yaml}\n\`\`\`\n\nReview it in the Policy Editor before applying it.`,
      };
      setMessages((prev) => [...prev, assistantMessage]);
      setPolicy(yaml);
    } catch (error) {
      const errorMessage: Message = {
        role: 'assistant',
        content: 'Sorry, I encountered an error generating draft YAML. Please try again.',
      };
      setMessages((prev) => [...prev, errorMessage]);
      toast.error('Failed to generate policy draft');
    } finally {
      setIsLoading(false);
    }
  };

  const handleReviewPolicy = async () => {
    try {
      setLoading(true);
      setCurrentView('policy');
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            'Draft moved to the Policy Editor for review. Apply it there once you are satisfied with the changes.',
        },
      ]);
      toast.success('Draft opened in Policy Editor');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Policy Assistant</h2>
        <p className="text-gray-600">
          Draft cryptographic policies using natural language, then review them before applying
        </p>
      </div>

      <div className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
        <div className="h-[500px] overflow-y-auto p-4 space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {message.role === 'assistant' && (
                <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-5 h-5 text-purple-600" />
                </div>
              )}
              <div
                className={`max-w-[70%] rounded-2xl p-4 ${
                  message.role === 'user'
                    ? 'bg-purple-600 text-white'
                    : 'bg-gray-100 text-gray-900'
                }`}
              >
                {message.role === 'assistant' && message.content.includes('```yaml') ? (
                  <div className="space-y-2">
                    <p>{message.content.split('```yaml')[0]}</p>
                    <pre className="bg-gray-800 text-green-400 p-3 rounded-lg overflow-x-auto text-sm">
                      {message.content.match(/```yaml\n([\s\S]*?)\n```/)?.[1]}
                    </pre>
                    <p>{message.content.split('```')[2]}</p>
                    {index === messages.length - 1 && (
                      <button
                        onClick={handleReviewPolicy}
                        className="mt-2 flex items-center gap-2 px-3 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
                      >
                        <Sparkles className="w-4 h-4" />
                        Review In Policy Editor
                      </button>
                    )}
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap">{message.content}</p>
                )}
              </div>
              {message.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                  <User className="w-5 h-5 text-blue-600" />
                </div>
              )}
            </div>
          ))}
          {isLoading && (
            <div className="flex gap-3 justify-start">
              <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center flex-shrink-0">
                <Bot className="w-5 h-5 text-purple-600" />
              </div>
              <div className="bg-gray-100 rounded-2xl p-4">
                <div className="flex gap-1">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-100" />
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-200" />
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="border-t border-gray-200 p-4 bg-gray-50">
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Describe your policy needs..."
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              disabled={isLoading}
            />
            <button
              onClick={handleSend}
              disabled={isLoading || !input.trim()}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-purple-400 transition-colors"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
