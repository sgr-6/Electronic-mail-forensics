import { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export default function AllCases() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Pagination & Filtering
  const [page, setPage] = useState(1);
  const [limit] = useState(50); // fetch 50 per page
  const [filterCategory, setFilterCategory] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchCases();
  }, [page]);

  const fetchCases = async () => {
    setLoading(true);
    try {
      // Offset based on page
      const offset = (page - 1) * limit;
      // In a real prod environment we'd pass filters to backend, 
      // but for this MVP we'll fetch a larger chunk and filter client side if needed, 
      // or just rely on backend pagination. The backend supports limit and offset.
      const res = await axios.get(`${API_URL}/cases?limit=${limit}&offset=${offset}`);
      setCases(res.data);
    } catch (error) {
      console.error("Error fetching all cases:", error);
    } finally {
      setLoading(false);
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

  // Client-side filtering for MVP speed
  const filteredCases = cases.filter(c => {
    const matchesSearch = c.subject.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          c.from_address.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = filterCategory === 'All' || c.risk_category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">All Analyzed Emails</h1>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        {/* Toolbar */}
        <div className="p-4 border-b border-gray-100 bg-gray-50 flex flex-wrap gap-4 justify-between items-center">
          <div className="relative flex-1 max-w-md">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-gray-400" />
            </div>
            <input
              type="text"
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
              placeholder="Search by subject or sender..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          
          <div className="flex items-center gap-2">
            <Filter className="h-5 w-5 text-gray-400" />
            <select
              className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-lg"
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
            >
              <option value="All">All Categories</option>
              <option value="Clean">Clean</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Phishing / BEC Attack">Phishing / BEC Attack</option>
              <option value="Malicious Infrastructure">Malicious Infrastructure</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-500">
            <thead className="text-xs text-gray-700 uppercase bg-gray-50 border-b">
              <tr>
                <th className="px-6 py-3">ID / Date</th>
                <th className="px-6 py-3">Subject</th>
                <th className="px-6 py-3">Sender</th>
                <th className="px-6 py-3">Risk Score</th>
                <th className="px-6 py-3">Category</th>
                <th className="px-6 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                    <div className="flex justify-center mb-2">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    </div>
                    Loading cases...
                  </td>
                </tr>
              ) : filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-gray-500">
                    No cases match your filters.
                  </td>
                </tr>
              ) : (
                filteredCases.map((c) => (
                  <tr key={c.id} className="bg-white border-b hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="font-medium text-gray-900">#{c.id.substring(0,8)}...</div>
                      <div className="text-xs text-gray-400 mt-1">{new Date(c.submitted_at || Date.now()).toLocaleDateString()}</div>
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-900 truncate max-w-[200px]">{c.subject}</td>
                    <td className="px-6 py-4 truncate max-w-[200px]">{c.from_address}</td>
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
                    <td className="px-6 py-4 text-right">
                      <Link to={`/case/${c.id}`} className="text-blue-600 hover:text-blue-800 hover:underline font-medium">
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination controls */}
        {!loading && cases.length >= limit && (
          <div className="p-4 border-t bg-gray-50 flex justify-center">
             <button 
                onClick={() => setPage(p => p + 1)}
                className="px-4 py-2 bg-white border border-gray-300 rounded-lg text-sm font-medium hover:bg-gray-50"
             >
               Load More (Page {page + 1})
             </button>
          </div>
        )}
      </div>
    </div>
  );
}
