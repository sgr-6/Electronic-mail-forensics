import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { FileText, Download } from 'lucide-react';
import { format } from 'date-fns';

const API_URL = 'http://localhost:8000/api';

export default function Reports() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const response = await axios.get(`${API_URL}/cases`);
        setCases(response.data);
      } catch (error) {
        console.error("Failed to load cases", error);
      } finally {
        setLoading(false);
      }
    };
    fetchCases();
  }, []);

  const handleDownload = (caseId: string) => {
    window.open(`${API_URL}/cases/${caseId}/report`, '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <FileText className="w-6 h-6 text-indigo-600" />
            Generated Reports
          </h1>
          <p className="text-gray-500 mt-1">
            Download comprehensive PDF forensic reports for analyzed cases.
          </p>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                <th className="text-left py-4 px-6 text-xs font-semibold text-gray-500 tracking-wider">CASE ID</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-gray-500 tracking-wider">DATE</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-gray-500 tracking-wider">SUBJECT</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-gray-500 tracking-wider">RISK CATEGORY</th>
                <th className="text-right py-4 px-6 text-xs font-semibold text-gray-500 tracking-wider">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-gray-500">Loading reports...</td>
                </tr>
              ) : cases.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-gray-500">No reports available.</td>
                </tr>
              ) : (
                cases.map((c) => (
                  <tr key={c.id} className="hover:bg-gray-50 transition-colors">
                    <td className="py-4 px-6 text-sm font-medium text-gray-900">
                      {c.id.substring(0, 8)}...
                    </td>
                    <td className="py-4 px-6 text-sm text-gray-500">
                      {format(new Date(c.submitted_at), 'MMM d, yyyy HH:mm')}
                    </td>
                    <td className="py-4 px-6 text-sm text-gray-900 truncate max-w-xs">
                      {c.subject || 'No Subject'}
                    </td>
                    <td className="py-4 px-6 text-sm font-medium">
                      <span className={`px-2 py-1 rounded-full text-xs ${
                        c.risk_category === 'Clean' ? 'bg-green-100 text-green-700' :
                        c.risk_category === 'Suspicious' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-red-100 text-red-700'
                      }`}>
                        {c.risk_category}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right">
                      <button
                        onClick={() => handleDownload(c.id)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 bg-indigo-50 text-indigo-600 rounded-lg hover:bg-indigo-100 transition-colors text-sm font-medium"
                      >
                        <Download className="w-4 h-4" />
                        PDF
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
