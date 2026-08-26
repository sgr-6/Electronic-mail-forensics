import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { ShieldAlert, ShieldCheck, MailWarning, UploadCloud } from 'lucide-react';

const API_URL = 'http://localhost:8000/api';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [cases, setCases] = useState<any[]>([]);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, casesRes] = await Promise.all([
        axios.get(`${API_URL}/stats`),
        axios.get(`${API_URL}/cases?limit=10`)
      ]);
      setStats(statsRes.data);
      setCases(casesRes.data);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setUploading(true);
    try {
      await axios.post(`${API_URL}/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      fetchData(); // Refresh data after successful upload
    } catch (error) {
      console.error("Upload failed", error);
      alert("Failed to analyze email. See console for details.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Clean': return 'bg-green-100 text-green-800';
      case 'Suspicious': return 'bg-yellow-100 text-yellow-800';
      case 'Phishing / BEC Attack': return 'bg-orange-100 text-orange-800';
      case 'Malicious Infrastructure': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Bar: Upload & Stats */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Platform Overview</h1>
        
        <div>
          <input 
            type="file" 
            accept=".eml" 
            className="hidden" 
            ref={fileInputRef}
            onChange={handleFileUpload}
          />
          <button 
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50"
          >
            <UploadCloud className="w-5 h-5" />
            {uploading ? 'Analyzing...' : 'Upload .EML'}
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Total Analyzed</p>
                <p className="text-3xl font-bold text-gray-900 mt-1">{stats.total_cases}</p>
              </div>
              <div className="p-2 bg-blue-50 rounded-lg"><MailWarning className="w-6 h-6 text-blue-600" /></div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Malicious/Phishing</p>
                <p className="text-3xl font-bold text-red-600 mt-1">
                  {stats.by_category['Phishing / BEC Attack'] || 0 + (stats.by_category['Malicious Infrastructure'] || 0)}
                </p>
              </div>
              <div className="p-2 bg-red-50 rounded-lg"><ShieldAlert className="w-6 h-6 text-red-600" /></div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Suspicious</p>
                <p className="text-3xl font-bold text-yellow-600 mt-1">{stats.by_category['Suspicious'] || 0}</p>
              </div>
              <div className="p-2 bg-yellow-50 rounded-lg"><MailWarning className="w-6 h-6 text-yellow-600" /></div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Clean</p>
                <p className="text-3xl font-bold text-green-600 mt-1">{stats.by_category['Clean'] || 0}</p>
              </div>
              <div className="p-2 bg-green-50 rounded-lg"><ShieldCheck className="w-6 h-6 text-green-600" /></div>
            </div>
          </div>
        </div>
      )}

      {/* Recent Cases Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <div className="p-6 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">Recent Analyses</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-500">
            <thead className="text-xs text-gray-700 uppercase bg-gray-50">
              <tr>
                <th className="px-6 py-3">ID</th>
                <th className="px-6 py-3">Subject</th>
                <th className="px-6 py-3">Sender</th>
                <th className="px-6 py-3">Risk Score</th>
                <th className="px-6 py-3">Category</th>
                <th className="px-6 py-3">Threat Type</th>
                <th className="px-6 py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {cases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-gray-500">
                    No emails analyzed yet. Upload an .EML file to begin.
                  </td>
                </tr>
              ) : cases.map((c) => (
                <tr key={c.id} className="bg-white border-b hover:bg-gray-50">
                  <td className="px-6 py-4 font-medium text-gray-900">#{c.id}</td>
                  <td className="px-6 py-4 truncate max-w-xs">{c.subject}</td>
                  <td className="px-6 py-4 truncate max-w-xs">{c.from_address}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-full bg-gray-200 rounded-full h-2.5 max-w-[60px]">
                        <div 
                          className={`h-2.5 rounded-full ${c.risk_score > 75 ? 'bg-red-600' : c.risk_score > 40 ? 'bg-yellow-400' : 'bg-green-500'}`}
                          style={{ width: `${c.risk_score}%` }}
                        ></div>
                      </div>
                      <span className="font-medium text-gray-700">{c.risk_score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${getCategoryColor(c.risk_category)}`}>
                      {c.risk_category}
                    </span>
                  </td>
                  <td className="px-6 py-4">{c.threat_type || '-'}</td>
                  <td className="px-6 py-4">
                    <Link to={`/case/${c.id}`} className="text-blue-600 hover:underline font-medium">View Report</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
