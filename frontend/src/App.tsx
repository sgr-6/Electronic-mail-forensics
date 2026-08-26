import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { Shield, LayoutDashboard, Share2, FileText, Database } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import CaseDetail from './pages/CaseDetail';
import CampaignGraph from './pages/CampaignGraph';
import Reports from './pages/Reports';
import SocHub from './pages/SocHub';
import AllCases from './pages/AllCases';

function App() {
  return (
      <div className="flex h-screen bg-gray-50 text-gray-900 font-sans">
        {/* Sidebar */}
        <aside className="w-64 bg-gray-900 text-white flex flex-col">
          <div className="p-6 border-b border-gray-800 flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            <span className="text-xl font-bold tracking-tight">AI Forensics</span>
          </div>
          
          <nav className="flex-1 p-4 space-y-2">
            <NavLink 
              to="/" 
              className={({isActive}) => `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
            >
              <LayoutDashboard className="w-5 h-5" />
              Dashboard
            </NavLink>
            <NavLink 
              to="/cases" 
              className={({isActive}) => `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
            >
              <Database className="w-5 h-5" />
              All Cases
            </NavLink>
            <NavLink 
              to="/graph" 
              className={({isActive}) => `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
            >
              <Share2 className="w-5 h-5" />
              Campaign Graph
            </NavLink>
            <NavLink 
              to="/reports" 
              className={({isActive}) => `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
            >
              <FileText className="w-5 h-5" />
              Reports
            </NavLink>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-auto bg-gray-50">
          <header className="bg-white shadow-sm border-b px-8 py-4">
            <h1 className="text-xl font-semibold text-gray-800">Email Threat Intelligence Platform</h1>
          </header>
          
          <div className="p-8">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/cases" element={<AllCases />} />
              <Route path="/case/:id" element={<CaseDetail />} />
              <Route path="/case/:id/soc" element={<SocHub />} />
              <Route path="/graph" element={<CampaignGraph />} />
              <Route path="/reports" element={<Reports />} />
            </Routes>
          </div>
        </main>
      </div>
  );
}

export default App;
