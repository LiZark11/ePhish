// frontend/src/App.js
import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Mail, AlertTriangle, BarChart3,
  Activity, Zap, Upload, Search,
  Clock, Download, MessageCircle, Send
} from 'lucide-react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [emailFile, setEmailFile] = useState(null);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [elapsedTime, setElapsedTime] = useState("00:00");
  const [forensicLogs, setForensicLogs] = useState([]);
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Hello! I am your forensic AI assistant. How can I help analyze this phishing case?' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [pdfDownloadUrl, setPdfDownloadUrl] = useState(null);

  const intervalRef = useRef(null);
  const startTimeRef = useRef(null);

  const [dashboardData] = useState({
    totalAnalyses: 127,
    phishingDetected: 23,
    malwareFound: 8,
    avgResponseTime: '2.3s',
    recentCases: [
      { id: 1, type: 'Phishing', severity: 'high', status: 'detected', timestamp: '2023-12-01 10:30:00' },
      { id: 2, type: 'Malware', severity: 'critical', status: 'quarantined', timestamp: '2023-12-01 09:45:00' },
      { id: 3, type: 'Clean', severity: 'low', status: 'approved', timestamp: '2023-12-01 08:20:00' }
    ],
    threatTrends: [
      { date: 'Dec 1', phishing: 5, malware: 2 },
      { date: 'Dec 2', phishing: 8, malware: 3 },
      { date: 'Dec 3', phishing: 12, malware: 1 },
      { date: 'Dec 4', phishing: 7, malware: 4 },
      { date: 'Dec 5', phishing: 15, malware: 6 }
    ]
  });

  // Simulate progress and timer
  useEffect(() => {
    if (isLoading) {
      startTimeRef.current = new Date();
      setProgress(0);
      setElapsedTime("00:00");

      intervalRef.current = setInterval(() => {
        setProgress(prev => Math.min(prev + 5, 95));
        const elapsed = Math.floor((Date.now() - startTimeRef.current) / 1000);
        const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
        const ss = String(elapsed % 60).padStart(2, '0');
        setElapsedTime(`${mm}:${ss}`);
      }, 1000);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        setProgress(100);
        
        if (startTimeRef.current) {
          const finalElapsed = Math.floor((Date.now() - startTimeRef.current) / 1000);
          const mm_final = String(Math.floor(finalElapsed / 60)).padStart(2, '0');
          const ss_final = String(finalElapsed % 60).padStart(2, '0');
          setElapsedTime(`${mm_final}:${ss_final}`);
        }
      }
    }

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isLoading]);

  const handleFileUpload = async (type) => {
    if (!emailFile) return;

    setIsLoading(true);
    setProgress(0);
    setElapsedTime("00:00");
    setAnalysisResults(null);
    setPdfDownloadUrl(null);

    try {
      const formData = new FormData();
      formData.append('file', emailFile);

      let endpoint;
      if (type === 'phishing') {
        endpoint = 'email/analyze';
      } else if (type === 'malware') {
        endpoint = 'malware/analyze';
      }

      const response = await axios.post(`http://localhost:8000/api/${endpoint}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 43200000 // 12 Jam
      });

      setAnalysisResults(response.data);

      if (response.data.report_pdf_path) {
        const pdfUrl = `http://localhost:8000/reports/${response.data.report_pdf_path}`;
        setPdfDownloadUrl(pdfUrl);
      } else {
        setPdfDownloadUrl(null);
      }

      setForensicLogs(prev => [...prev, {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        action: `${type} analysis`,
        result: response.data.verdict || 'completed',
        severity: response.data.severity || 'info'
      }]);

    } catch (err) {
      console.error('Analysis error:', err);
      let uiErrorMessage = "Terjadi kesalahan sistem yang tidak diketahui.";

      if (err.code === 'ECONNABORTED') {
        uiErrorMessage = "⏱️ TIMEOUT: Sistem macet atau dataset terlalu besar untuk diproses dalam batas waktu.";
      } else if (err.message === 'Network Error' || err.code === 'ERR_NETWORK') {
        uiErrorMessage = "💥 CRASH / MATI: Koneksi ke server terputus di tengah analisis. Kemungkinan Analyzer kehabisan RAM (Out of Memory) atau terjadi error fatal. Buka terminal Docker untuk melihat traceback errornya.";
      } else if (err.response) {
        const status = err.response.status;
        const detail = err.response.data?.detail || err.response.data || "Tidak ada detail error.";
        uiErrorMessage = `⚠️ ERROR DARI SERVER (Status ${status}):\n${detail}`;
      }
      
      setAnalysisResults({ error: uiErrorMessage });
      setPdfDownloadUrl(null);
    } finally {
      setIsLoading(false);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      setProgress(0);
      setElapsedTime("00:00");
    }
  };

  const handleChatSubmit = async () => {
    if (!chatInput.trim() || !analysisResults) return;

    setChatMessages(prev => [
      ...prev,
      { role: 'user', content: chatInput }
    ]);

    try {
      const response = await axios.post('http://localhost:8000/api/ai/explain', {
        query: chatInput,
        analysis_data: analysisResults
      });

      setChatMessages(prev => [
        ...prev,
        { role: 'assistant', content: response.data.explanation }
      ]);
    } catch (err) {
      setChatMessages(prev => [
        ...prev,
        { role: 'assistant', content: 'Sorry, I encountered an error processing your request.' }
      ]);
    }

    setChatInput('');
  };

  const renderBatchDetails = (rows) => {
    if (!rows || rows.length === 0) return <p>No rows to display.</p>;

    const displayedRows = rows.slice(0, 50);
    const hasMore = rows.length > 50;

    return (
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-600">
          <thead>
            <tr>
              <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Email ID</th>
              <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Phishing</th>
              <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Confidence</th>
              <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Severity</th>
              <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Social Eng.</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-600">
            {displayedRows.map((row, index) => (
              <tr key={index}>
                <td className="px-4 py-2 text-sm text-gray-300">{row.email_id || `Row ${index + 1}`}</td>
                <td className="px-4 py-2 text-sm">
                  <span className={`px-2 py-1 rounded text-xs ${row.phishing ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'}`}>
                    {row.phishing ? 'YES' : 'NO'}
                  </span>
                </td>
                <td className="px-4 py-2 text-sm text-gray-300">{(row.confidence || 0).toFixed(4)}</td>
                <td className="px-4 py-2 text-sm">
                  <span className={`px-2 py-1 rounded text-xs ${
                    row.severity === 'CRITICAL' ? 'bg-red-900 text-red-200' :
                    row.severity === 'HIGH' ? 'bg-orange-900 text-orange-200' : 'bg-green-900 text-green-200'
                  }`}>
                    {row.severity || 'N/A'}
                  </span>
                </td>
                <td className="px-4 py-2 text-sm text-gray-300">{row.social_engineering || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {hasMore && (
          <p className="text-sm text-gray-500 mt-2">... and {rows.length - 50} more rows</p>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-red-500" />
            <h1 className="text-2xl font-bold">ePhish</h1>
            <span className="text-sm text-gray-400">Digital Forensic Platform</span>
          </div>
          <div className="flex items-center space-x-4">
            <Activity className="w-5 h-5 text-green-500 animate-pulse" />
            <span className="text-sm text-gray-300">System Operational</span>
          </div>
        </div>
      </header>

      <nav className="bg-gray-800 border-b border-gray-700 px-6 py-3">
        <div className="flex space-x-6">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'phishing', label: 'Email Phishing', icon: Mail },
            { id: 'malware', label: 'Email Malware', icon: AlertTriangle },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id ? 'bg-red-600 text-white' : 'text-gray-300 hover:text-white hover:bg-gray-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </nav>

      <main className="p-6">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400">Total Analyses</p>
                    <p className="text-2xl font-bold text-blue-400">{dashboardData.totalAnalyses}</p>
                  </div>
                  <BarChart3 className="w-8 h-8 text-blue-400" />
                </div>
              </div>
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400">Phishing Detected</p>
                    <p className="text-2xl font-bold text-red-400">{dashboardData.phishingDetected}</p>
                  </div>
                  <Mail className="w-8 h-8 text-red-400" />
                </div>
              </div>
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400">Malware Found</p>
                    <p className="text-2xl font-bold text-orange-400">{dashboardData.malwareFound}</p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-orange-400" />
                </div>
              </div>
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400">Avg Response Time</p>
                    <p className="text-2xl font-bold text-green-400">{dashboardData.avgResponseTime}</p>
                  </div>
                  <Zap className="w-8 h-8 text-green-400" />
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Threat Trends</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboardData.threatTrends}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="date" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" />
                    <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }} />
                    <Line type="monotone" dataKey="phishing" stroke="#EF4444" strokeWidth={2} />
                    <Line type="monotone" dataKey="malware" stroke="#F59E0B" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Recent Cases</h3>
                <div className="space-y-3">
                  {dashboardData.recentCases.map((caseItem) => (
                    <div key={caseItem.id} className="flex items-center justify-between p-3 bg-gray-700 rounded">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${
                          caseItem.severity === 'critical' ? 'bg-red-500' :
                          caseItem.severity === 'high' ? 'bg-orange-500' : 'bg-yellow-500'
                        }`} />
                        <span>{caseItem.type}</span>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-400">{caseItem.status}</p>
                        <p className="text-xs text-gray-500">{caseItem.timestamp}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'phishing' && (
          <div className="space-y-6">
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <Mail className="w-5 h-5 mr-2 text-red-400" />
                Email Phishing Analysis
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Upload Email File (.eml, .csv, .msg)</label>
                  <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center">
                    <Upload className="w-12 h-12 text-gray-400 mx-auto mb-2" />
                    <input type="file" accept=".eml,.csv,.msg" onChange={(e) => setEmailFile(e.target.files[0])} className="hidden" id="email-upload" />
                    <label htmlFor="email-upload" className="cursor-pointer">
                      <span className="text-blue-400 hover:text-blue-300">Click to upload or drag and drop</span>
                    </label>
                    {emailFile && (<p className="text-sm text-gray-400 mt-2">{emailFile.name}</p>)}
                  </div>
                </div>
                <button onClick={() => handleFileUpload('phishing')} disabled={isLoading || !emailFile} className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-2 rounded-lg flex items-center">
                  <Search className="w-4 h-4 mr-2" /> Analyze Email
                </button>
                {isLoading && (
                  <div className="space-y-2">
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div className="bg-red-600 h-2.5 rounded-full transition-all duration-300 ease-out" style={{ width: `${progress}%` }}></div>
                    </div>
                    <div className="flex justify-between text-sm text-gray-400">
                      <span>Progress: {progress}%</span>
                      <span><Clock className="w-4 h-4 inline mr-1" />{elapsedTime}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {analysisResults && !isLoading && (
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>
                {analysisResults.error ? (
                  <div className="bg-red-900/50 border border-red-500 text-red-200 p-6 rounded-lg shadow-lg">
                    <div className="flex items-center mb-3">
                      <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                      <h3 className="text-xl font-bold text-red-400">Analisis Gagal / Sistem Error</h3>
                    </div>
                    <p className="text-sm whitespace-pre-wrap font-mono bg-black/30 p-3 rounded border border-red-800">{analysisResults.error}</p>
                    <p className="text-xs text-red-300 mt-3">
                      <strong>Tips:</strong> Jika error "Network Error", segera buka terminal Kali Linux Anda dan lihat log <code>docker compose</code>. Cari tulisan berwarna merah (Traceback) untuk melihat penyebab pasti crash-nya.
                    </p>
                  </div>
                ) : analysisResults.rows ? ( // ✅ Cek langsung key 'rows' untuk batch CSV
                  <div>
                    <h4 className="font-medium mb-2 text-blue-400">CSV Batch Analysis Summary</h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      <div className="bg-gray-700 p-3 rounded"><p className="text-sm text-gray-400">Total Rows</p><p className="text-lg font-semibold">{analysisResults.total_rows}</p></div>
                      <div className="bg-gray-700 p-3 rounded"><p className="text-sm text-gray-400">Phishing Detected</p><p className="text-lg font-semibold text-red-400">{analysisResults.phishing_count}</p></div>
                      <div className="bg-gray-700 p-3 rounded"><p className="text-sm text-gray-400">Clean Emails</p><p className="text-lg font-semibold text-green-400">{analysisResults.clean_count}</p></div>
                    </div>
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a href={pdfDownloadUrl} download={`ePhish_Batch_Report_${emailFile?.name || 'analysis'}.pdf`} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center">
                          <Download className="w-4 h-4 mr-2" /> Download PDF Report
                        </a>
                      </div>
                    )}
                    {renderBatchDetails(analysisResults.rows)}
                  </div>
                ) : (
                  <div>
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a href={pdfDownloadUrl} download={`ePhish_Single_Email_Report_${emailFile?.name || 'analysis'}.pdf`} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center">
                          <Download className="w-4 h-4 mr-2" /> Download PDF Report
                        </a>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div className="space-y-2">
                        <p><strong>Phishing Verdict:</strong> <span className={analysisResults.phishing ? 'text-red-400' : 'text-green-400'}>{analysisResults.phishing ? 'PHISHING DETECTED' : 'CLEAN'}</span></p>
                        <p><strong>Confidence:</strong> {(analysisResults.confidence * 100).toFixed(2)}%</p>
                        <p><strong>Severity:</strong> <span className={analysisResults.severity === 'CRITICAL' ? 'text-red-400' : analysisResults.severity === 'HIGH' ? 'text-orange-400' : 'text-green-400'}>{analysisResults.severity}</span></p>
                      </div>
                      <div className="space-y-2">
                        <p><strong>Social Engineering:</strong> {analysisResults.social_engineering || 'None detected'}</p>
                      </div>
                    </div>
                    <div className="mt-4 p-4 bg-gray-700 rounded">
                      <h4 className="font-medium mb-1">Explanation</h4>
                      <p className="text-sm text-gray-300">{analysisResults.explanation}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'malware' && (
          <div className="space-y-6">
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2 text-orange-400" />
                Email Malware Analysis
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Upload Email or Attachment</label>
                  <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center">
                    <Upload className="w-12 h-12 text-gray-400 mx-auto mb-2" />
                    <input type="file" onChange={(e) => setEmailFile(e.target.files[0])} className="hidden" id="malware-upload" />
                    <label htmlFor="malware-upload" className="cursor-pointer">
                      <span className="text-orange-400 hover:text-orange-300">Click to upload email (.eml/.msg) or attachment file</span>
                    </label>
                    {emailFile && (<p className="text-sm text-gray-400 mt-2">{emailFile.name}</p>)}
                  </div>
                </div>
                <button onClick={() => handleFileUpload('malware')} disabled={isLoading || !emailFile} className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 px-6 py-2 rounded-lg flex items-center">
                  <Search className="w-4 h-4 mr-2" /> Analyze Malware
                </button>
                {isLoading && (
                  <div className="space-y-2">
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div className="bg-orange-600 h-2.5 rounded-full transition-all duration-300 ease-out" style={{ width: `${progress}%` }}></div>
                    </div>
                    <div className="flex justify-between text-sm text-gray-400">
                      <span>Progress: {progress}%</span>
                      <span><Clock className="w-4 h-4 inline mr-1" />{elapsedTime}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {analysisResults && !isLoading && (
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Malware Analysis Results</h3>
                {analysisResults.error ? (
                  <div className="text-red-400">Error: {analysisResults.error}</div>
                ) : (
                  <div>
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a href={pdfDownloadUrl} download={`ePhish_Malware_Report_${emailFile?.name || 'analysis'}.pdf`} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center">
                          <Download className="w-4 h-4 mr-2" /> Download PDF Report
                        </a>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <p><strong>Malware Status:</strong> <span className={analysisResults.is_malware ? 'text-red-400' : 'text-green-400'}>{analysisResults.is_malware ? 'MALWARE DETECTED' : 'CLEAN'}</span></p>
                        <p><strong>Malware Family:</strong> {analysisResults.malware_family || 'Unknown'}</p>
                        <p><strong>Confidence:</strong> {(analysisResults.malware_confidence * 100).toFixed(2)}%</p>
                        <p><strong>Analysis Method:</strong> {analysisResults.analysis_method}</p>
                      </div>
                      <div className="space-y-2">
                        <p><strong>File Hash:</strong> {analysisResults.file_hash}</p>
                        <p><strong>Entropy:</strong> {analysisResults.entropy?.toFixed(4)}</p>
                        <p><strong>YARA Matches:</strong> {analysisResults.yara_matches?.length || 0}</p>
                        <p><strong>Suspicious Patterns:</strong> {analysisResults.suspicious_patterns_found?.length || 0}</p>
                      </div>
                    </div>
                    <div className="mt-4 p-4 bg-gray-700 rounded">
                      <h4 className="font-medium mb-1">Explanation</h4>
                      <p className="text-sm text-gray-300">{analysisResults.explanation}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        <div className="mt-6 bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <MessageCircle className="w-5 h-5 mr-2 text-purple-400" />
            AI Forensic Assistant
          </h3>
          <div className="space-y-4">
            <div className="bg-gray-700 p-4 rounded max-h-64 overflow-y-auto">
              {chatMessages.map((message, index) => (
                <div key={index} className={`mb-3 ${message.role === 'user' ? 'text-right' : ''}`}>
                  <div className={`inline-block p-3 rounded-lg max-w-xs ${message.role === 'user' ? 'bg-blue-600 text-white' : 'bg-gray-600 text-white'}`}>
                    {message.content}
                  </div>
                </div>
              ))}
            </div>
            <div className="flex space-x-2">
              <input type="text" value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask about analysis results, forensic procedures, or incident response..." className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white" onKeyPress={(e) => e.key === 'Enter' && handleChatSubmit()} />
              <button onClick={handleChatSubmit} className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg flex items-center">
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6 bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-green-400" />
            Forensic Activity Logs
          </h3>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-600">
              <thead>
                <tr>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Timestamp</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Action</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Result</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-600">
                {[...forensicLogs].reverse().map((log, index) => (
                  <tr key={log.id || index}>
                    <td className="px-4 py-2 text-sm text-gray-300">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-2 text-sm text-gray-300">{log.action}</td>
                    <td className="px-4 py-2 text-sm">
                      <span className={`px-2 py-1 rounded text-xs ${log.result.toLowerCase().includes('detect') || log.result.toLowerCase().includes('quarantin') ? 'bg-red-900 text-red-200' : log.result.toLowerCase().includes('approv') || log.result.toLowerCase().includes('clean') ? 'bg-green-900 text-green-200' : 'bg-gray-900 text-gray-200'}`}>
                        {log.result}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm">
                      <span className={`px-2 py-1 rounded text-xs ${log.severity === 'critical' ? 'bg-red-900 text-red-200' : log.severity === 'high' ? 'bg-orange-900 text-orange-200' : log.severity === 'medium' ? 'bg-yellow-900 text-yellow-200' : 'bg-green-900 text-green-200'}`}>
                        {log.severity.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;