import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, Link } from 'react-router-dom';
import { 
    Terminal, 
    FileKey, 
    DownloadCloud, 
    AlertTriangle, 
    Search,
    Coins,
    Code,
    Network
} from 'lucide-react';

const API_URL = 'http://localhost:8000/api';

export default function SocHub() {
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    const fetchSocData = async () => {
      try {
        const response = await axios.post(`${API_URL}/soc/analyze-extended/${id}`);
        setData(response.data);
      } catch (error) {
        console.error("SOC analysis failed", error);
      } finally {
        setLoading(false);
      }
    };
    if (id) fetchSocData();
  }, [id]);

  if (loading) {
    return <div className="flex h-[50vh] items-center justify-center text-gray-500">Executing Deep SOC Analysis...</div>;
  }

  if (!data) {
    return <div className="text-red-500">Failed to load SOC details.</div>;
  }

  const { smuggling, crypto, fingerprints } = data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Terminal className="w-6 h-6 text-red-600" />
            SOC Active Response Hub
          </h1>
          <p className="text-gray-500 mt-1">Deep threat extraction and active defense actions for Case #{id}</p>
        </div>
        <Link to={`/case/${id}`} className="px-4 py-2 text-sm font-medium text-blue-600 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors">
          &larr; Back to Case
        </Link>
      </div>

      {/* Action Bar */}
      <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-100 flex flex-wrap gap-4">
        <a 
          href={`${API_URL}/soc/bsa-certificate/${id}`} 
          target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors text-sm font-medium"
        >
          <FileKey className="w-4 h-4" /> BSA Sec 63 PDF
        </a>
        <a 
          href={`${API_URL}/soc/i4c-docket/${id}`} 
          target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
        >
          <DownloadCloud className="w-4 h-4" /> Export I4C Docket
        </a>
        <a 
          href={`${API_URL}/soc/takedown-notice/${id}`} 
          target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm font-medium"
        >
          <AlertTriangle className="w-4 h-4" /> Takedown Notice
        </a>
        <a 
          href={`${API_URL}/soc/rules/${id}`} 
          target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm font-medium"
        >
          <Code className="w-4 h-4" /> YARA / Suricata Rules
        </a>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* HTML Smuggling */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Search className="w-5 h-5 text-orange-500" />
            HTML Smuggling & Base64 Inspector
          </h2>
          
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-medium text-gray-700 mb-2">Indicators Detected</h3>
              {smuggling?.indicators?.length > 0 ? (
                <ul className="list-disc pl-5 text-sm text-red-600 space-y-1">
                  {smuggling.indicators.map((ind: string, i: number) => <li key={i}>{ind}</li>)}
                </ul>
              ) : (
                <p className="text-sm text-green-600">No client-side smuggling vectors detected.</p>
              )}
            </div>

            {smuggling?.smuggled_files?.length > 0 && (
              <div className="mt-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Embedded Payloads</h3>
                <div className="space-y-2">
                  {smuggling.smuggled_files.map((file: any, i: number) => (
                    <div key={i} className="p-3 bg-gray-50 border border-gray-200 rounded-lg text-sm">
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-semibold text-gray-800">{file.detected_type}</span>
                        {file.is_spoofed && <span className="px-2 py-0.5 bg-red-100 text-red-700 text-xs rounded-full font-medium">MIME Spoof</span>}
                      </div>
                      <div className="text-gray-500 text-xs break-all font-mono mt-2">
                        SHA256: {file.sha256}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Crypto Ledger */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Coins className="w-5 h-5 text-yellow-500" />
            Crypto Extortion Ledger
          </h2>
          
          {crypto?.extracted_wallets?.length > 0 ? (
            <div className="space-y-3">
              {crypto.extracted_wallets.map((wallet: any, i: number) => (
                <div key={i} className={`p-4 border rounded-lg ${wallet.is_illicit ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-bold text-gray-800 flex items-center gap-2">
                      {wallet.currency} Wallet
                      {wallet.is_illicit && <span className="px-2 py-0.5 bg-red-600 text-white text-xs rounded-full">Illicit Funds</span>}
                    </span>
                    <span className="text-sm font-medium text-gray-600">Bal: {wallet.balance}</span>
                  </div>
                  <code className="text-xs text-gray-600 bg-white px-2 py-1 rounded block mb-2">{wallet.address}</code>
                  <p className="text-xs text-gray-500 text-right">Mock Txns: {wallet.transaction_count}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No cryptocurrency wallets detected in payload.</p>
          )}
        </div>

        {/* Infra Fingerprints */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 lg:col-span-2">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Network className="w-5 h-5 text-indigo-500" />
            Infrastructure Fingerprinting
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-gray-50 rounded-lg">
              <h3 className="text-sm font-medium text-gray-500 mb-1">X-Mailer</h3>
              <p className="text-gray-900 font-mono text-sm">{fingerprints?.x_mailer || 'Not specified'}</p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <h3 className="text-sm font-medium text-gray-500 mb-1">User-Agent</h3>
              <p className="text-gray-900 font-mono text-sm">{fingerprints?.user_agent || 'Not specified'}</p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg md:col-span-2">
              <h3 className="text-sm font-medium text-gray-500 mb-2">TLS Cipher Suites Detected</h3>
              <div className="flex flex-wrap gap-2">
                {fingerprints?.tls_ciphers?.length > 0 ? (
                  fingerprints.tls_ciphers.map((c: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-indigo-100 text-indigo-700 text-xs rounded-md font-mono">{c}</span>
                  ))
                ) : (
                  <span className="text-sm text-gray-500">None detected</span>
                )}
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
