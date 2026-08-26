import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { ShieldAlert, ShieldCheck, MailWarning, UploadCloud, Mail } from 'lucide-react';

const API_URL = 'http://localhost:8000/api';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [cases, setCases] = useState<any[]>([]);
  const [uploading, setUploading] = useState(false);
  
  // IMAP Modal State
  const [showImapModal, setShowImapModal] = useState(false);
  const [imapForm, setImapForm] = useState({
    server: 'imap.gmail.com',
    email: '',
    password: '',
    limit: 5
  });
  const [imapLoading, setImapLoading] = useState(false);
  const [imapError, setImapError] = useState('');
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

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

  // Drag & Drop State
  const [isDragging, setIsDragging] = useState(false);

  const processFiles = async (files: FileList | File[]) => {
    if (!files || files.length === 0) return;

    setUploading(true);
    let successCount = 0;
    
    try {
      // Process files sequentially to avoid overwhelming the server
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (!file.name.endsWith('.eml') && !file.name.endsWith('.txt')) {
          console.warn(`Skipping ${file.name}, not an .eml file`);
          continue;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        await axios.post(`${API_URL}/analyze`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        successCount++;
      }
      
      if (successCount > 0) {
        fetchData(); // Refresh data after successful uploads
      } else {
        alert("No valid .eml files were found to upload.");
      }
    } catch (error) {
      console.error("Upload failed", error);
      alert("Failed to analyze some emails. See console for details.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      processFiles(event.target.files);
    }
  };

  const onDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files) {
      processFiles(e.dataTransfer.files);
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
        
        <div className="flex gap-2">
          <button 
            onClick={() => setShowImapModal(true)}
            className="flex items-center gap-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Mail className="w-5 h-5" />
            Fetch from Gmail
          </button>
          
          <input 
            type="file" 
            accept=".eml" 
            multiple
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
            {uploading ? 'Analyzing...' : 'Upload .EML(s)'}
          </button>
        </div>
      </div>

      {/* Drag & Drop Area */}
      <div 
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
          isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300 bg-gray-50 hover:bg-gray-100'
        }`}
      >
        <div className="flex flex-col items-center justify-center space-y-2">
          <div className={`p-3 rounded-full ${isDragging ? 'bg-blue-100 text-blue-600' : 'bg-gray-200 text-gray-500'}`}>
            <UploadCloud className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-gray-900">
            {uploading ? 'Uploading and analyzing emails...' : 'Drag & Drop .EML files here'}
          </h3>
          <p className="text-sm text-gray-500">
            Select or drop multiple `.eml` files to batch analyze them instantly.
          </p>
          <button 
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="mt-4 text-sm font-medium text-blue-600 hover:text-blue-700 underline"
          >
            Or click to browse files
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
                  {(stats.phishing_count || 0) + (stats.malicious_count || 0)}
                </p>
              </div>
              <div className="p-2 bg-red-50 rounded-lg"><ShieldAlert className="w-6 h-6 text-red-600" /></div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Suspicious</p>
                <p className="text-3xl font-bold text-yellow-600 mt-1">{stats.suspicious_count || 0}</p>
              </div>
              <div className="p-2 bg-yellow-50 rounded-lg"><MailWarning className="w-6 h-6 text-yellow-600" /></div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm font-medium text-gray-500">Clean</p>
                <p className="text-3xl font-bold text-green-600 mt-1">{stats.clean_count || 0}</p>
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

      {/* IMAP Modal */}
      {showImapModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-xl shadow-xl w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Fetch Emails from Gmail (IMAP)</h2>
            <p className="text-sm text-gray-600 mb-4">
              Enter your Gmail address and an <a href="https://support.google.com/accounts/answer/185833" target="_blank" rel="noreferrer" className="text-blue-600 underline">App Password</a> (not your normal password).
            </p>
            
            {imapError && (
              <div className="bg-red-50 text-red-700 p-3 rounded-lg text-sm mb-4">
                {imapError}
              </div>
            )}
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email Address</label>
                <input 
                  type="email" 
                  value={imapForm.email}
                  onChange={(e) => setImapForm({...imapForm, email: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  placeholder="investigator@gmail.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">App Password</label>
                <input 
                  type="password" 
                  value={imapForm.password}
                  onChange={(e) => setImapForm({...imapForm, password: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  placeholder="16-character app password"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Number of Emails to Fetch</label>
                <input 
                  type="number" 
                  min="1" max="20"
                  value={imapForm.limit}
                  onChange={(e) => setImapForm({...imapForm, limit: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 border rounded-lg"
                />
              </div>
            </div>
            
            <div className="mt-6 flex justify-end gap-3">
              <button 
                onClick={() => setShowImapModal(false)}
                className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-lg"
                disabled={imapLoading}
              >
                Cancel
              </button>
              <button 
                onClick={async () => {
                  setImapLoading(true);
                  setImapError('');
                  try {
                    await axios.post(`${API_URL}/imap/fetch`, {
                      imap_server: imapForm.server,
                      email_user: imapForm.email,
                      app_password: imapForm.password,
                      limit: imapForm.limit
                    });
                    setShowImapModal(false);
                    fetchData();
                  } catch (err: any) {
                    setImapError(err.response?.data?.detail || "Failed to fetch emails.");
                  } finally {
                    setImapLoading(false);
                  }
                }}
                disabled={imapLoading || !imapForm.email || !imapForm.password}
                className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50"
              >
                {imapLoading ? 'Fetching & Analyzing...' : 'Fetch Emails'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
