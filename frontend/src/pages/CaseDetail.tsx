import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';
import { ArrowLeft, Download, AlertTriangle, ShieldCheck, FileText, Link as LinkIcon, Map } from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';

// Fix leaflet icon issue in react
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export default function CaseDetail() {
  const { id } = useParams();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCase = async () => {
      try {
        const res = await axios.get(`${API_URL}/cases/${id}`);
        setData(res.data);
      } catch (error) {
        console.error("Failed to load case", error);
      } finally {
        setLoading(false);
      }
    };
    fetchCase();
  }, [id]);

  if (loading) return <div className="p-8 text-center text-gray-500">Loading case data...</div>;
  if (!data) return <div className="p-8 text-center text-red-500">Case not found.</div>;

  const { hops = [], attachments = [], urls = [], ...email } = data;

  let nlpData = null;
  try {
    // Check if it's a JSON string, otherwise use the object directly
    if (email.nlp_details_json) {
      nlpData = typeof email.nlp_details_json === 'string' 
        ? JSON.parse(email.nlp_details_json) 
        : email.nlp_details_json;
    }
  } catch (e) {
    console.error("Failed to parse NLP data", e);
  }

  // Prepare map data
  const mapHops = hops.filter((h: any) => h.latitude && h.longitude);
  const positions: [number, number][] = mapHops.map((h: any) => [h.latitude, h.longitude]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <Link to="/" className="flex items-center text-gray-500 hover:text-gray-900 mb-4 transition-colors">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Link>
          <div className="flex items-center gap-4">
            <h1 className="text-3xl font-bold text-gray-900">Case #{email.id}</h1>
            <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
              email.risk_score > 75 ? 'bg-red-100 text-red-800' : 
              email.risk_score > 40 ? 'bg-yellow-100 text-yellow-800' : 
              'bg-green-100 text-green-800'
            }`}>
              {email.risk_category} (Score: {email.risk_score})
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <Link
            to={`/case/${id}/soc`}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <AlertTriangle className="w-5 h-5" />
            SOC Active Response
          </Link>
          <a 
            href={`${API_URL}/cases/${id}/report`}
            target="_blank"
            className="flex items-center gap-2 bg-gray-900 hover:bg-gray-800 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Download className="w-5 h-5" />
            Export PDF Report
          </a>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Metadata & NLP */}
        <div className="lg:col-span-2 space-y-6">
          
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 border-b pb-3 mb-4">Email Metadata</h2>
            <div className="grid grid-cols-6 gap-4 text-sm">
              <div className="col-span-1 font-medium text-gray-500">Subject</div>
              <div className="col-span-5 text-gray-900 font-medium">{email.subject}</div>
              
              <div className="col-span-1 font-medium text-gray-500">From</div>
              <div className="col-span-5 text-gray-900">{email.from_display} &lt;{email.from_address}&gt;</div>
              
              <div className="col-span-1 font-medium text-gray-500">To</div>
              <div className="col-span-5 text-gray-900">{email.to_address}</div>
              
              <div className="col-span-1 font-medium text-gray-500">Date</div>
              <div className="col-span-5 text-gray-900">{email.date_header}</div>
              
              <div className="col-span-1 font-medium text-gray-500">Message-ID</div>
              <div className="col-span-5 text-gray-600 break-all">{email.message_id}</div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 border-b pb-3 mb-4">NLP Threat Analysis</h2>
            {nlpData ? (
              <div className="space-y-4">
                <div className="flex gap-4">
                  <div className="bg-gray-50 p-4 rounded-lg flex-1">
                    <p className="text-sm text-gray-500 mb-1">Classification</p>
                    <p className="font-semibold text-gray-900">{nlpData.classification || 'Unknown'}</p>
                  </div>
                  <div className="bg-gray-50 p-4 rounded-lg flex-1">
                    <p className="text-sm text-gray-500 mb-1">Confidence</p>
                    <p className="font-semibold text-gray-900">{nlpData.confidence ? (nlpData.confidence * 100).toFixed(1) : 0}%</p>
                  </div>
                </div>
                {nlpData.indicators && nlpData.indicators.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-2">Triggered Indicators:</p>
                    <ul className="list-disc pl-5 space-y-1 text-sm text-red-600">
                      {nlpData.indicators.map((ind: string, i: number) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No NLP analysis data available.</p>
            )}
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 border-b pb-3 mb-4">Authentication Results</h2>
            <div className="grid grid-cols-3 gap-4">
              <AuthCard name="SPF" result={email.spf_result} />
              <AuthCard name="DKIM" result={email.dkim_result} />
              <AuthCard name="DMARC" result={email.dmarc_result} />
            </div>
          </div>
          
        </div>

        {/* Right Column: Entities (URLs, Attachments) */}
        <div className="space-y-6">
          
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2 mb-4">
              <LinkIcon className="w-5 h-5 text-gray-500" /> Extracted URLs ({urls.length})
            </h2>
            <div className="space-y-3 max-h-80 overflow-y-auto pr-2">
              {urls.length === 0 ? <p className="text-sm text-gray-500">No URLs found.</p> : urls.map((u: any) => (
                <div key={u.id} className={`p-3 rounded-lg border ${u.is_suspicious ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
                  <p className="text-sm font-mono break-all text-gray-800">{u.domain}</p>
                  {u.is_suspicious && (
                    <p className="text-xs text-red-600 mt-2 flex items-start gap-1">
                      <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                      {u.suspicion_reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2 mb-4">
              <FileText className="w-5 h-5 text-gray-500" /> Attachments ({attachments.length})
            </h2>
            <div className="space-y-3 max-h-80 overflow-y-auto pr-2">
              {attachments.length === 0 ? <p className="text-sm text-gray-500">No attachments found.</p> : attachments.map((a: any) => (
                <div key={a.id} className="p-3 rounded-lg border border-gray-200 bg-gray-50">
                  <p className="text-sm font-medium text-gray-900 truncate">{a.filename}</p>
                  <div className="flex justify-between mt-1">
                    <span className="text-xs text-gray-500">{a.content_type}</span>
                    <span className="text-xs text-gray-500">{(a.size / 1024).toFixed(1)} KB</span>
                  </div>
                  <p className="text-xs text-gray-400 font-mono mt-2 truncate" title={a.hash_sha256}>
                    SHA256: {a.hash_sha256}
                  </p>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>

      {/* Map Section */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2 mb-4">
          <Map className="w-5 h-5 text-gray-500" /> Hop-by-Hop Trace
        </h2>
        
        <div className="h-96 w-full rounded-lg border border-gray-200 overflow-hidden mb-6 z-0">
          {positions.length > 0 ? (
            <MapContainer center={positions[0]} zoom={2} className="h-full w-full">
              <TileLayer
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              />
              {mapHops.map((hop: any, idx: number) => (
                <Marker key={idx} position={[hop.latitude, hop.longitude]}>
                  <Popup>
                    <strong>Hop {hop.sequence}</strong><br/>
                    IP: {hop.ip_address}<br/>
                    Location: {hop.city}, {hop.country}<br/>
                    ISP: {hop.isp}
                  </Popup>
                </Marker>
              ))}
              {positions.length > 1 && <Polyline positions={positions} color="red" dashArray="5, 10" />}
            </MapContainer>
          ) : (
            <div className="h-full flex items-center justify-center bg-gray-50 text-gray-500">
              No geographical data available for these hops.
            </div>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-500">
            <thead className="text-xs text-gray-700 uppercase bg-gray-50">
              <tr>
                <th className="px-4 py-2">Seq</th>
                <th className="px-4 py-2">IP Address</th>
                <th className="px-4 py-2">Location</th>
                <th className="px-4 py-2">ISP</th>
                <th className="px-4 py-2">Type</th>
              </tr>
            </thead>
            <tbody>
              {hops.map((hop: any) => (
                <tr key={hop.id} className="border-b">
                  <td className="px-4 py-3">{hop.sequence}</td>
                  <td className="px-4 py-3 font-mono">{hop.ip_address || '-'}</td>
                  <td className="px-4 py-3">{hop.country ? `${hop.city ? hop.city + ', ' : ''}${hop.country}` : '-'}</td>
                  <td className="px-4 py-3">{hop.isp || '-'}</td>
                  <td className="px-4 py-3">
                    {hop.is_originating ? <span className="text-red-600 font-medium">Originating</span> : 
                     hop.is_private ? <span className="text-gray-400">Internal</span> : 
                     <span className="text-blue-600">Relay</span>}
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

function AuthCard({ name, result }: { name: string, result: string }) {
  const isPass = result?.toLowerCase() === 'pass';
  const isFail = result?.toLowerCase() === 'fail' || result?.toLowerCase() === 'softfail';
  
  return (
    <div className={`p-4 rounded-lg border ${isPass ? 'bg-green-50 border-green-200' : isFail ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-200'}`}>
      <p className="text-sm font-medium text-gray-500">{name}</p>
      <div className="flex items-center gap-2 mt-1">
        {isPass ? <ShieldCheck className="w-5 h-5 text-green-600" /> : isFail ? <AlertTriangle className="w-5 h-5 text-red-600" /> : null}
        <p className={`font-bold uppercase ${isPass ? 'text-green-700' : isFail ? 'text-red-700' : 'text-gray-600'}`}>
          {result || 'N/A'}
        </p>
      </div>
    </div>
  );
}
