// frontend/src/App.js
import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Mail, AlertTriangle, BarChart3,
  Activity, Zap, Upload, Search,
  Clock, Download, RotateCcw
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
  const [progress, setProgress] = useState(0); // 0-100
  const [elapsedTime, setElapsedTime] = useState("00:00"); // MM:SS
  const [forensicLogs, setForensicLogs] = useState([]);
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Hello! I am your forensic AI assistant. How can I help analyze this phishing case?' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [pdfDownloadUrl, setPdfDownloadUrl] = useState(null); // State untuk URL download PDF

  const intervalRef = useRef(null);
  const startTimeRef = useRef(null);

  // Mock dashboard data
  const [dashboardData, setDashboardData] = useState({
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
        setProgress(prev => {
          const newProgress = Math.min(prev + 5, 95); // Naik 5% per detik, max 95%
          return newProgress;
        });

        const now = new Date();
        const elapsed = Math.floor((now - startTimeRef.current) / 1000);
        const minutes = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const seconds = (elapsed % 60).toString().padStart(2, '0');
        setElapsedTime(`${minutes}:${seconds}`);
      }, 1000);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        // Set progress to 100% when done
        setProgress(100);
        // Stop timer
        const now = new Date();
        const elapsed = Math.floor((now - startTimeRef.current) / 1000);
        const minutes = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const seconds = (elapsed % 60).toString().padStart(2, '0');
        setElapsedTime(`${minutes}:${seconds}`);
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isLoading]);

  const handleFileUpload = async (type) => {
    if (!emailFile) return; // Semua jenis file diupload melalui satu input file

    setIsLoading(true);
    setProgress(0);
    setElapsedTime("00:00");
    setAnalysisResults(null); // Reset hasil sebelumnya
    setPdfDownloadUrl(null); // Reset PDF URL sebelumnya

    try {
      const formData = new FormData();
      formData.append('file', emailFile);

      let endpoint;
      if (type === 'phishing') {
        endpoint = 'email/analyze'; // Sekarang endpoint ini menangani gabungan
      } else if (type === 'malware') {
        endpoint = 'malware/analyze'; // Endpoint standalone jika diperlukan
      }

      // Gunakan axios.post biasa, backend handle timeout
      const response = await axios.post(`http://localhost:8000/api/${endpoint}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setAnalysisResults(response.data);

      // Cek apakah ada path PDF untuk diunduh
      if (response.data.report_pdf_path) {
        // Ambil nama file dari path (misalnya path berisi /tmp/filename.pdf)
        const fileName = response.data.report_pdf_path.split('/').pop();
        // Kita asumsikan backend memiliki endpoint untuk mengunduh file ini
        // Misalnya, backend mengekspor file dari /tmp ke folder statis yang bisa diakses, atau gunakan streaming
        // Untuk sementara, kita gunakan format URL seperti ini, sesuaikan dengan endpoint download PDF di backend Anda
        // Contoh: jika backend bisa serve file dari /reports/filename.pdf
        // setPdfDownloadUrl(`http://localhost:8000/reports/${fileName}`);
        // ATAU jika backend menyediakan endpoint GET seperti yang ditambahkan di langkah 2:
        setPdfDownloadUrl(`http://localhost:8000/reports/${fileName}`);
      } else {
        setPdfDownloadUrl(null); // Reset jika tidak ada PDF
      }

      // Add to forensic logs
      setForensicLogs(prev => [...prev, {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        action: `${type} analysis`,
        result: response.data.verdict || 'completed',
        severity: response.data.severity || 'info'
      }]);

    } catch (error) {
      console.error('Analysis error:', error);
      setAnalysisResults({ error: error.message });
      setPdfDownloadUrl(null); // Pastikan PDF URL direset jika error
    } finally {
      setIsLoading(false);
      // Reset timer dan progress setelah selesai
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      setProgress(0);
      setElapsedTime("00:00");
    }
  };

  const handleChatSubmit = async () => {
    if (!chatInput.trim()) return;

    const userMessage = { role: 'user', content: chatInput };
    setChatMessages(prev => [...prev, userMessage]);

    try {
      const response = await axios.post('http://localhost:8000/api/ai/explain', {
        query: chatInput,
        analysis_data: analysisResults
      });

      const aiMessage = { role: 'assistant', content: response.data.explanation };
      setChatMessages(prev => [...prev, aiMessage]);
    } catch (error) {
      const errorMessage = { role: 'assistant', content: 'Sorry, I encountered an error processing your request.' };
      setChatMessages(prev => [...prev, errorMessage]);
    }

    setChatInput('');
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
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

      {/* Navigation */}
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
                activeTab === tab.id 
                  ? 'bg-red-600 text-white' 
                  : 'text-gray-300 hover:text-white hover:bg-gray-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </nav>

      {/* Main Content */}
      <main className="p-6">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Stats Cards */}
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

            {/* Charts and Recent Cases */}
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
                    <input
                      type="file"
                      accept=".eml,.csv,.msg"
                      onChange={(e) => setEmailFile(e.target.files[0])}
                      className="hidden"
                      id="email-upload"
                    />
                    <label htmlFor="email-upload" className="cursor-pointer">
                      <span className="text-blue-400 hover:text-blue-300">
                        Click to upload or drag and drop
                      </span>
                    </label>
                    {emailFile && (
                      <p className="text-sm text-gray-400 mt-2">{emailFile.name}</p>
                    )}
                  </div>
                </div>
                
                <button
                  onClick={() => handleFileUpload('phishing')}
                  disabled={!emailFile || isLoading}
                  className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-2 rounded-lg flex items-center"
                >
                  <Search className="w-4 h-4 mr-2" />
                  Analyze Email
                </button>

                {/* Progress Bar and Timer */}
                {isLoading && (
                  <div className="space-y-2">
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div 
                        className="bg-red-600 h-2.5 rounded-full transition-all duration-300 ease-out" 
                        style={{ width: `${progress}%` }}
                      ></div>
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
                  <div className="text-red-400">Error: {analysisResults.error}</div>
                ) : analysisResults.csv_analysis ? ( // Jika hasil batch CSV
                  <div>
                    <h4 className="font-medium mb-2">CSV Analysis Summary</h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      <div>
                        <p className="text-sm text-gray-400">Total Rows</p>
                        <p className="text-lg font-semibold">{analysisResults.csv_analysis.total_rows}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Phishing Detected</p>
                        <p className="text-lg font-semibold text-red-400">{analysisResults.csv_analysis.phishing_count}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Clean Emails</p>
                        <p className="text-lg font-semibold text-green-400">{analysisResults.csv_analysis.clean_count}</p>
                      </div>
                    </div>
                    {/* Cek dan tampilkan tombol download PDF untuk batch */}
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a
                          href={pdfDownloadUrl}
                          download
                          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center"
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download PDF Report
                        </a>
                      </div>
                    )}
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-gray-600">
                        <thead>
                          <tr>
                            <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Email ID</th>
                            <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Phishing</th>
                            <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Confidence</th>
                            <th className="px-4 py-2 text-left text-sm font-medium text-gray-300">Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-600">
                          {analysisResults.csv_analysis.rows?.slice(0, 10).map((row, index) => ( // Tampilkan 10 baris pertama
                            <tr key={index}>
                              <td className="px-4 py-2 text-sm text-gray-300">{row.email_id}</td>
                              <td className="px-4 py-2 text-sm">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  row.phishing ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'
                                }`}>
                                  {row.phishing ? 'YES' : 'NO'}
                                </span>
                              </td>
                              <td className="px-4 py-2 text-sm text-gray-300">{row.confidence?.toFixed(4)}</td>
                              <td className="px-4 py-2 text-sm">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  row.severity === 'CRITICAL' ? 'bg-red-900 text-red-200' :
                                  row.severity === 'HIGH' ? 'bg-orange-900 text-orange-200' : 'bg-green-900 text-green-200'
                                }`}>
                                  {row.severity}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {analysisResults.csv_analysis.rows?.length > 10 && (
                      <p className="text-sm text-gray-500 mt-2">... and {analysisResults.csv_analysis.rows.length - 10} more rows</p>
                    )}
                  </div>
                ) : ( // Jika hasil single email (gabungan)
                  <div>
                    {/* Tombol Download PDF jika tersedia */}
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a
                          href={pdfDownloadUrl}
                          download
                          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center"
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download PDF Report
                        </a>
                      </div>
                    )}
                    {/* Render hasil phishing */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div className="space-y-2">
                        <p><strong>Phishing Verdict:</strong> <span className={
                          analysisResults.phishing ? 'text-red-400' : 'text-green-400'
                        }>
                          {analysisResults.phishing ? 'PHISHING DETECTED' : 'CLEAN'}
                        </span></p>
                        <p><strong>Confidence (Phishing):</strong> {(analysisResults.confidence * 100).toFixed(2)}%</p>
                        <p><strong>Severity:</strong> <span className={
                          analysisResults.severity === 'CRITICAL' ? 'text-red-400' :
                          analysisResults.severity === 'HIGH' ? 'text-orange-400' : 'text-green-400'
                        }>{analysisResults.severity}</span></p>
                        <p><strong>Phishing Score:</strong> {analysisResults.confidence?.toFixed(4)}</p>
                      </div>
                      <div className="space-y-2">
                        <p><strong>Suspicious URLs:</strong> {analysisResults.urls?.length || 0}</p>
                        <p><strong>Social Engineering:</strong> {analysisResults.social_engineering?.join(', ') || 'None detected'}</p>
                        <p><strong>NLP Label:</strong> {analysisResults.nlp_label}</p>
                      </div>
                    </div>
                    {/* Render hasil malware jika ada */}
                    {analysisResults.malware_analysis && (
                      <div className="mt-4 pt-4 border-t border-gray-600">
                        <h4 className="font-medium mb-2">Malware Analysis (Email Content)</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <p><strong>Malware Status:</strong> <span className={
                              analysisResults.malware_analysis.is_malware ? 'text-red-400' : 'text-green-400'
                            }>
                              {analysisResults.malware_analysis.is_malware ? 'MALWARE DETECTED' : 'CLEAN'}
                            </span></p>
                            <p><strong>Malware Family:</strong> {analysisResults.malware_analysis.malware_family || 'Unknown'}</p>
                            <p><strong>Confidence (Malware):</strong> {(analysisResults.malware_analysis.malware_confidence * 100).toFixed(2)}%</p>
                          </div>
                          <div className="space-y-2">
                            <p><strong>Entropy:</strong> {analysisResults.malware_analysis.entropy?.toFixed(4)}</p>
                            <p><strong>YARA Matches:</strong> {analysisResults.malware_analysis.yara_matches?.length || 0}</p>
                            <p><strong>Analysis Method:</strong> {analysisResults.malware_analysis.analysis_method}</p>
                          </div>
                        </div>
                      </div>
                    )}
                    {/* Penjelasan */}
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
                    <input
                      type="file"
                      onChange={(e) => setEmailFile(e.target.files[0])} // Gunakan state yang sama
                      className="hidden"
                      id="malware-upload"
                    />
                    <label htmlFor="malware-upload" className="cursor-pointer">
                      <span className="text-orange-400 hover:text-orange-300">
                        Click to upload email (.eml/.msg) or attachment file
                      </span>
                    </label>
                    {emailFile && (
                      <p className="text-sm text-gray-400 mt-2">{emailFile.name}</p>
                    )}
                  </div>
                </div>
                
                <button
                  onClick={() => handleFileUpload('malware')}
                  disabled={!emailFile || isLoading}
                  className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 px-6 py-2 rounded-lg flex items-center"
                >
                  <Search className="w-4 h-4 mr-2" />
                  Analyze Malware
                </button>

                {/* Progress Bar and Timer */}
                {isLoading && (
                  <div className="space-y-2">
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div 
                        className="bg-orange-600 h-2.5 rounded-full transition-all duration-300 ease-out" 
                        style={{ width: `${progress}%` }}
                      ></div>
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
                    {/* Tombol Download PDF jika tersedia */}
                    {pdfDownloadUrl && (
                      <div className="mb-4">
                        <a
                          href={pdfDownloadUrl}
                          download
                          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg inline-flex items-center"
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download PDF Report
                        </a>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <p><strong>Malware Status:</strong> <span className={
                          analysisResults.is_malware ? 'text-red-400' : 'text-green-400'
                        }>
                          {analysisResults.is_malware ? 'MALWARE DETECTED' : 'CLEAN'}
                        </span></p>
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
                    {/* Penjelasan */}
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

      </main>
    </div>
  );
};

export default App;
