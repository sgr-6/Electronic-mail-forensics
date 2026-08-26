import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';
import CytoscapeComponent from 'react-cytoscapejs';
import { Share2, Crosshair } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export default function CampaignGraph() {
  const [elements, setElements] = useState<any>([]);
  const [loading, setLoading] = useState(true);
  const [latestCaseId, setLatestCaseId] = useState<string | null>(null);
  const cyRef = useRef<any>(null);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        // 1. Fetch graph data
        const response = await axios.get(`${API_URL}/graph`);
        const graphData = response.data;
        
        // 2. Fetch the most recent case to focus on
        try {
          const casesRes = await axios.get(`${API_URL}/cases?limit=1`);
          if (casesRes.data && casesRes.data.length > 0) {
            setLatestCaseId(casesRes.data[0].id);
          }
        } catch (e) {
          console.error("Could not fetch latest case for focusing", e);
        }

        // Convert NetworkX node/link format to Cytoscape elements
        const cyElements = [];
        
        if (graphData.nodes) {
          graphData.nodes.forEach((node: any) => {
            cyElements.push({
              data: {
                id: node.id,
                label: node.label || node.id,
                type: node.group || node.type, // Map group to type for cy
                risk: node.risk_score || 0
              }
            });
          });
        }
        
        if (graphData.edges) { // Use edges instead of links
          graphData.edges.forEach((edge: any, index: number) => {
            cyElements.push({
              data: {
                id: `e${index}`,
                source: edge.source,
                target: edge.target,
                label: edge.label || edge.type || ''
              }
            });
          });
        }
        
        setElements(cyElements);
      } catch (error) {
        console.error("Failed to load graph", error);
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, []);

  // Function to focus the graph on the most recent case
  const focusLatestCase = () => {
    if (cyRef.current && latestCaseId) {
      const node = cyRef.current.getElementById(latestCaseId);
      if (node.length > 0) {
        cyRef.current.animate({
          fit: { eles: node.closedNeighborhood(), padding: 50 },
          duration: 1000,
          easing: 'ease-in-out'
        });
        // Highlight the node temporarily
        node.style({'border-width': 4, 'border-color': '#fde047', 'background-color': '#eab308'});
        setTimeout(() => {
          node.removeStyle();
        }, 3000);
      }
    }
  };

  const layout = {
    name: 'cose',
    animate: true,
    animationDuration: 500,
    nodeDimensionsIncludeLabels: true,
    idealEdgeLength: 150,
    nodeOverlap: 20,
    refresh: 20,
    fit: true,
    padding: 40,
    randomize: true,
    componentSpacing: 150,
    nodeRepulsion: 4000000,
    edgeElasticity: 50,
    nestingFactor: 5,
    gravity: 80,
    numIter: 1000,
  };

  const style: any = [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 6,
        'font-size': '11px',
        'font-family': 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto',
        'font-weight': '600',
        'color': '#1f2937',
        'text-outline-color': '#ffffff',
        'text-outline-width': 3,
        'background-color': '#94a3b8',
        'width': 48,
        'height': 48,
        'border-width': 2,
        'border-color': '#ffffff',
        'shadow-blur': 10,
        'shadow-color': '#000000',
        'shadow-opacity': 0.1,
      }
    },
    {
      selector: 'node[type = "Email"]',
      style: { 'background-color': '#3b82f6', 'shape': 'rectangle' } // blue
    },
    {
      selector: 'node[type = "IP"]',
      style: { 'background-color': '#ef4444', 'shape': 'diamond' } // red
    },
    {
      selector: 'node[type = "Domain"]',
      style: { 'background-color': '#f59e0b', 'shape': 'hexagon' } // orange
    },
    {
      selector: 'node[type = "ASN"]',
      style: { 'background-color': '#8b5cf6', 'shape': 'round-rectangle' } // purple
    },
    {
      selector: 'node[type = "Campaign"]',
      style: { 'background-color': '#ec4899', 'shape': 'star', 'width': 64, 'height': 64, 'border-width': 3, 'border-color': '#fbcfe8' } // pink
    },
    {
      selector: 'node[type = "Mailer"]',
      style: { 'background-color': '#10b981', 'shape': 'triangle' } // emerald
    },
    {
      selector: 'node[type = "UserAgent"]',
      style: { 'background-color': '#14b8a6', 'shape': 'diamond' } // teal
    },
    {
      selector: 'node[type = "TLSCipher"]',
      style: { 'background-color': '#6366f1', 'shape': 'hexagon' } // indigo
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#cbd5e1',
        'target-arrow-color': '#cbd5e1',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '10px',
        'font-family': 'ui-sans-serif, system-ui',
        'text-rotation': 'autorotate',
        'text-margin-y': -12,
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.8,
        'text-background-padding': 2,
        'color': '#64748b'
      }
    }
  ];

  return (
    <div className="space-y-6 h-[calc(100vh-8rem)] flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Share2 className="w-6 h-6 text-blue-600" />
            Campaign Graph
          </h1>
          <p className="text-gray-500 mt-1">
            Visualizes relationships between emails, infrastructure (IPs, domains), and threat campaigns.
          </p>
        </div>
        
        {latestCaseId && (
          <button 
            onClick={focusLatestCase}
            className="flex items-center gap-2 bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Crosshair className="w-5 h-5" />
            Focus Recent Investigation
          </button>
        )}
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 flex-1 overflow-hidden relative">
        
        {/* Legend */}
        <div className="absolute top-4 left-4 bg-white/90 backdrop-blur border border-gray-200 p-3 rounded-lg shadow-sm z-10 text-xs">
          <h3 className="font-semibold text-gray-700 mb-2">Legend</h3>
          <div className="space-y-2">
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-blue-500 rounded-sm"></div><span>Email</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-red-500 rotate-45 transform"></div><span>IP Address</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-orange-500 clip-hexagon"></div><span>Domain</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-purple-500 rounded-md"></div><span>ASN</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-emerald-500" style={{clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)'}}></div><span>Mailer</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-indigo-500 clip-hexagon"></div><span>Cipher</span></div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 bg-pink-500 rounded-full"></div><span>Campaign</span></div>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-full text-gray-500">Loading graph...</div>
        ) : elements.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">No graph data available. Upload cases to build the graph.</div>
        ) : (
          <CytoscapeComponent 
            cy={(cy) => { cyRef.current = cy; }}
            elements={elements} 
            layout={layout} 
            stylesheet={style}
            style={ { width: '100%', height: '100%', backgroundColor: '#f8fafc' } }
            minZoom={0.2}
            maxZoom={3}
            wheelSensitivity={0.1}
          />
        )}
      </div>
    </div>
  );
}
