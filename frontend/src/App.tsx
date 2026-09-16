import { useState, useEffect } from 'react';
import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Share2, FileText, Database, Menu, X } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import CaseDetail from './pages/CaseDetail';
import CampaignGraph from './pages/CampaignGraph';
import Reports from './pages/Reports';
import SocHub from './pages/SocHub';
import AllCases from './pages/AllCases';

function App() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  const navLinks = (
    <>
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
    </>
  );

  return (
    <div className="flex h-dvh bg-gray-50 text-gray-900 font-sans">
      {/* Mobile Sidebar Overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-40 flex md:hidden">
          <div className="fixed inset-0 bg-black/50" onClick={() => setMobileMenuOpen(false)} />
          <aside className="relative w-64 bg-gray-900 text-white flex flex-col h-full">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className="w-8 h-8 text-blue-500" />
                <span className="text-xl font-bold tracking-tight">AI Forensics</span>
              </div>
              <button onClick={() => setMobileMenuOpen(false)} className="p-1 text-gray-400 hover:text-white">
                <X className="w-6 h-6" />
              </button>
            </div>
            <nav className="flex-1 p-4 space-y-2">
              {navLinks}
            </nav>
          </aside>
        </div>
      )}

      {/* Desktop Sidebar */}
      <aside className="hidden md:flex md:w-64 bg-gray-900 text-white flex-col">
        <div className="p-6 border-b border-gray-800 flex items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500" />
          <span className="text-xl font-bold tracking-tight">AI Forensics</span>
        </div>
        
        <nav className="flex-1 p-4 space-y-2">
          {navLinks}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-gray-50">
        {/* Mobile Header Bar */}
        <div className="md:hidden flex items-center gap-3 bg-gray-900 text-white px-4 py-3 sticky top-0 z-30">
          <button onClick={() => setMobileMenuOpen(true)} className="p-1">
            <Menu className="w-6 h-6" />
          </button>
          <Shield className="w-6 h-6 text-blue-500" />
          <span className="text-lg font-bold tracking-tight">AI Forensics</span>
        </div>

        <header className="bg-white shadow-sm border-b px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-xl font-semibold text-gray-800">Email Threat Intelligence Platform</h1>
        </header>
        
        <div className="p-4 sm:p-6 lg:p-8">
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
