import { Routes, Route, Link } from 'react-router-dom';
import { Shield, LayoutDashboard, Share2, FileText } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import CaseDetail from './pages/CaseDetail';

function App() {
  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-4 flex items-center gap-3 border-b border-gray-800">
          <Shield className="text-blue-500 w-8 h-8" />
          <h1 className="font-bold text-lg tracking-tight">AI Forensics</h1>
        </div>
        
        <nav className="flex-1 p-4 space-y-2">
          <Link to="/" className="flex items-center gap-3 px-3 py-2 rounded-lg bg-gray-800 text-gray-200 hover:bg-gray-700 hover:text-white transition-colors">
            <LayoutDashboard className="w-5 h-5" />
            Dashboard
          </Link>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-lg text-gray-400 hover:bg-gray-800 hover:text-white transition-colors">
            <Share2 className="w-5 h-5" />
            Campaign Graph
          </a>
          <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-lg text-gray-400 hover:bg-gray-800 hover:text-white transition-colors">
            <FileText className="w-5 h-5" />
            Reports
          </a>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-gray-50">
        <header className="bg-white shadow-sm border-b px-8 py-4">
          <h2 className="text-xl font-semibold text-gray-800">Email Threat Intelligence Platform</h2>
        </header>
        
        <div className="p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/case/:id" element={<CaseDetail />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}

export default App;
