import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileOutput, Play, Square, Settings,
  Activity, Clock, Files, Zap, ChevronRight, Info, X,
  Plus, Trash2, FileText, Check
} from 'lucide-react'

// Wails runtime - will be available when running in Wails
const runtime = window.runtime
const go = window.go

// Available parsers list
const parsers = [
  { category: 'Windows', items: [
    { name: 'Windows Event Log', ext: '.evtx', desc: 'Binary Windows Event Log files' },
    { name: 'Windows Firewall', ext: 'pfirewall.log', desc: 'Windows Firewall logs' },
    { name: 'Windows Text Logs', ext: '.log', desc: 'CBS, WindowsUpdate, SetupAPI, DISM logs' },
    { name: 'Prefetch', ext: '.pf', desc: 'Windows Prefetch files' },
    { name: 'Scheduled Tasks', ext: '.xml', desc: 'Windows Scheduled Task XML exports' },
    { name: 'Windows Event XML', ext: '.xml', desc: 'Exported Windows Events (wevtutil)' },
  ]},
  { category: 'Linux/Unix', items: [
    { name: 'Syslog', ext: 'syslog, auth.log', desc: 'Linux syslog files (RFC 3164/5424)' },
    { name: 'iptables/UFW', ext: '.log', desc: 'Linux firewall logs' },
  ]},
  { category: 'macOS', items: [
    { name: 'Unified Log', ext: '.log', desc: 'macOS Unified Log exports (log show)' },
    { name: 'Install Log', ext: 'install.log', desc: 'macOS installation logs' },
    { name: 'ASL', ext: 'system.log', desc: 'Apple System Log (legacy)' },
  ]},
  { category: 'Web Servers', items: [
    { name: 'Apache/Nginx', ext: 'access.log', desc: 'Combined Log Format access logs' },
    { name: 'IIS', ext: 'u_ex*.log', desc: 'Microsoft IIS W3C Extended logs' },
  ]},
  { category: 'Network Security', items: [
    { name: 'Zeek/Bro', ext: 'conn.log, dns.log', desc: 'Zeek network security logs' },
    { name: 'Cisco ASA', ext: '.log', desc: 'Cisco ASA/PIX firewall logs' },
  ]},
  { category: 'Cloud Platforms', items: [
    { name: 'AWS CloudTrail', ext: '.json', desc: 'AWS CloudTrail audit logs' },
    { name: 'Azure Activity', ext: '.json', desc: 'Azure Activity Log exports' },
    { name: 'GCP Audit', ext: '.json', desc: 'Google Cloud Audit logs' },
  ]},
  { category: 'PowerShell', items: [
    { name: 'Transcripts', ext: '.txt', desc: 'PowerShell transcript files' },
    { name: 'Script Block', ext: '.txt, .xml', desc: 'Script Block Logging (Event 4104)' },
  ]},
  { category: 'Browser Forensics', items: [
    { name: 'Chrome/Edge', ext: 'History', desc: 'Chromium browser history (SQLite)' },
    { name: 'Firefox', ext: 'places.sqlite', desc: 'Firefox browser history' },
    { name: 'Safari', ext: 'History.db', desc: 'Safari browser history' },
  ]},
  { category: 'Artifacts & Exports', items: [
    { name: 'CSV Artifacts', ext: '.csv', desc: 'MFTECmd, Plaso, KAPE exports' },
    { name: 'Sysmon XML', ext: '.xml', desc: 'Sysmon configuration and events' },
    { name: 'JSON/JSONL', ext: '.json, .jsonl', desc: 'Generic JSON log files' },
    { name: 'Generic Logs', ext: '.log, .txt', desc: 'Auto-detected timestamp formats' },
  ]},
]

function App() {
  const [inputFiles, setInputFiles] = useState([])
  const [outputPath, setOutputPath] = useState('')
  const [format, setFormat] = useState('jsonl')
  const [isProcessing, setIsProcessing] = useState(false)
  const [stats, setStats] = useState({ files: 0, events: 0, elapsed: '00:00', speed: 0 })
  const [progress, setProgress] = useState(0)
  const [startTime, setStartTime] = useState(null)
  const [showAbout, setShowAbout] = useState(false)

  const formats = [
    { id: 'jsonl', name: 'JSONL', desc: 'JSON Lines - Best for analysis tools' },
    { id: 'csv', name: 'CSV', desc: 'Spreadsheet compatible format' },
    { id: 'sqlite', name: 'SQLite', desc: 'Database for complex queries' },
  ]

  useEffect(() => {
    if (!runtime) return

    runtime.EventsOn('progress', (data) => {
      setStats(s => ({ ...s, files: data.files, events: data.events }))
      setProgress(data.percent || 0)
    })

    runtime.EventsOn('complete', () => {
      setIsProcessing(false)
    })

    return () => {
      runtime.EventsOff('progress')
      runtime.EventsOff('complete')
    }
  }, [])

  useEffect(() => {
    let interval
    if (isProcessing && startTime) {
      interval = setInterval(() => {
        const elapsed = Date.now() - startTime
        const mins = Math.floor(elapsed / 60000)
        const secs = Math.floor((elapsed % 60000) / 1000)
        const speed = Math.round(stats.events / (elapsed / 1000)) || 0
        setStats(s => ({
          ...s,
          elapsed: `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`,
          speed
        }))
      }, 1000)
    }
    return () => clearInterval(interval)
  }, [isProcessing, startTime, stats.events])

  const selectInput = async () => {
    if (!go) {
      // Demo mode - add some fake files
      setInputFiles(prev => [...prev, '/demo/logs/sample.evtx'])
      return
    }
    try {
      const files = await go.main.App.SelectInputFiles()
      if (files && files.length > 0) {
        // Add new files, avoiding duplicates
        setInputFiles(prev => {
          const existingPaths = new Set(prev)
          const newFiles = files.filter(f => !existingPaths.has(f))
          return [...prev, ...newFiles]
        })
      }
    } catch (e) {
      console.error('Error selecting input:', e)
    }
  }

  const removeFile = (index) => {
    setInputFiles(prev => prev.filter((_, i) => i !== index))
  }

  const clearAllFiles = () => {
    setInputFiles([])
  }

  // Helper to get just the filename from a path
  const getFileName = (path) => {
    return path.split(/[\\/]/).pop()
  }

  const selectOutput = async () => {
    if (!go) return setOutputPath('/demo/output')
    try {
      const path = await go.main.App.SelectOutputFolder()
      if (path) setOutputPath(path)
    } catch (e) {
      console.error('Error selecting output:', e)
    }
  }

  const startProcessing = async () => {
    if (inputFiles.length === 0 || !outputPath) return

    setIsProcessing(true)
    setStats({ files: 0, events: 0, elapsed: '00:00', speed: 0 })
    setProgress(0)
    setStartTime(Date.now())

    if (go) {
      try {
        await go.main.App.StartProcessing(inputFiles, outputPath, format)
      } catch (e) {
        console.error('Error starting processing:', e)
        setIsProcessing(false)
      }
    }
  }

  const stopProcessing = async () => {
    if (go) {
      try {
        await go.main.App.StopProcessing()
      } catch (e) {
        console.error('Error stopping:', e)
      }
    }
    setIsProcessing(false)
  }

  const canStart = inputFiles.length > 0 && outputPath && !isProcessing

  return (
    <div className="h-screen flex flex-col overflow-hidden select-none">
      {/* Header */}
      <header className="flex-shrink-0 glass border-b border-dark-700/30">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="absolute inset-0 bg-accent-blue rounded-xl blur-xl opacity-50" />
              <div className="relative icon-box from-accent-blue to-accent-cyan">
                <Zap className="w-5 h-5 text-white" />
              </div>
            </div>
            <div>
              <h1 className="text-xl font-bold glow-text">LogZero</h1>
              <p className="text-xs text-dark-400">DFIR Timeline Generator</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowAbout(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-dark-800/50 border border-dark-700/50 text-dark-300 hover:text-white hover:border-dark-600 transition-all text-sm"
            >
              <Info className="w-4 h-4" />
              About
            </button>
            <div className="h-4 w-px bg-dark-700" />
            <span className="badge-success">v1.0.0</span>
            <div className="h-4 w-px bg-dark-700" />
            <span className="text-sm text-dark-400">
              {isProcessing ? 'Processing...' : 'Ready'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto space-y-6">

          {/* Config Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Input Card */}
            <motion.div
              className="glass-card glass-hover p-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <div className="section-header mb-4">
                <div className="icon-box from-accent-blue to-blue-600">
                  <Files className="w-5 h-5 text-white" />
                </div>
                <span>Input Files</span>
                {inputFiles.length > 0 && (
                  <span className="ml-auto text-xs bg-accent-blue/20 text-accent-blue px-2 py-0.5 rounded-full">
                    {inputFiles.length} file{inputFiles.length !== 1 ? 's' : ''}
                  </span>
                )}
              </div>

              {/* Add Files Button */}
              <button
                onClick={selectInput}
                disabled={isProcessing}
                className="w-full btn-ghost text-left flex items-center justify-between group"
              >
                <span className="flex items-center gap-2">
                  <Plus className="w-4 h-4" />
                  {inputFiles.length === 0 ? 'Select Files' : 'Add More Files'}
                </span>
                <ChevronRight className="w-4 h-4 text-dark-500 group-hover:text-white transition-colors" />
              </button>

              {/* File List */}
              <AnimatePresence>
                {inputFiles.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-3"
                  >
                    <div className="max-h-40 overflow-y-auto space-y-1.5 p-2 bg-dark-800/50 rounded-lg border border-dark-700/30">
                      {inputFiles.map((file, index) => (
                        <motion.div
                          key={file}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: 10 }}
                          className="flex items-center gap-2 p-2 bg-dark-900/50 rounded-lg group"
                        >
                          <FileText className="w-4 h-4 text-accent-cyan shrink-0" />
                          <span className="text-xs font-mono text-dark-300 truncate flex-1" title={file}>
                            {getFileName(file)}
                          </span>
                          {!isProcessing && (
                            <button
                              onClick={() => removeFile(index)}
                              className="p-1 rounded hover:bg-red-500/20 text-dark-500 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                              title="Remove file"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </motion.div>
                      ))}
                    </div>

                    {/* Clear All Button */}
                    {!isProcessing && inputFiles.length > 1 && (
                      <button
                        onClick={clearAllFiles}
                        className="mt-2 text-xs text-dark-500 hover:text-red-400 transition-colors flex items-center gap-1"
                      >
                        <Trash2 className="w-3 h-3" />
                        Clear all files
                      </button>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Ready Indicator */}
              <AnimatePresence>
                {inputFiles.length > 0 && !isProcessing && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="mt-3 flex items-center gap-2 text-xs text-accent-green"
                  >
                    <Check className="w-4 h-4" />
                    <span>Ready to process</span>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Output Card */}
            <motion.div
              className="glass-card glass-hover p-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="section-header mb-4">
                <div className="icon-box from-accent-purple to-purple-600">
                  <FileOutput className="w-5 h-5 text-white" />
                </div>
                <span>Output Directory</span>
              </div>
              <button
                onClick={selectOutput}
                disabled={isProcessing}
                className="w-full btn-ghost text-left flex items-center justify-between group"
              >
                <span>Select Folder</span>
                <ChevronRight className="w-4 h-4 text-dark-500 group-hover:text-white transition-colors" />
              </button>
              <AnimatePresence>
                {outputPath && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-3 p-3 bg-dark-800/50 rounded-lg border border-dark-700/30"
                  >
                    <p className="text-xs text-dark-400 mb-1">Selected:</p>
                    <p className="text-sm font-mono text-accent-cyan truncate">{outputPath}</p>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Format Card */}
            <motion.div
              className="glass-card glass-hover p-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="section-header mb-4">
                <div className="icon-box from-accent-green to-emerald-600">
                  <Settings className="w-5 h-5 text-white" />
                </div>
                <span>Output Format</span>
              </div>
              <div className="space-y-2">
                {formats.map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setFormat(f.id)}
                    disabled={isProcessing}
                    className={`w-full p-3 rounded-xl text-left transition-all duration-200 ${
                      format === f.id
                        ? 'bg-accent-blue/20 border border-accent-blue/40 text-white'
                        : 'bg-dark-800/30 border border-transparent hover:bg-dark-700/50 text-dark-300'
                    }`}
                  >
                    <p className="font-medium text-sm">{f.name}</p>
                    <p className="text-xs opacity-60 mt-0.5">{f.desc}</p>
                  </button>
                ))}
              </div>
            </motion.div>
          </div>

          {/* Stats Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <motion.div className="stat-card" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.4 }}>
              <Files className="w-6 h-6 text-accent-blue" />
              <span className="stat-value">{stats.files.toLocaleString()}</span>
              <span className="stat-label">Files Processed</span>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.5 }}>
              <Activity className="w-6 h-6 text-accent-purple" />
              <span className="stat-value">{stats.events.toLocaleString()}</span>
              <span className="stat-label">Events Found</span>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.6 }}>
              <Clock className="w-6 h-6 text-accent-cyan" />
              <span className="stat-value">{stats.elapsed}</span>
              <span className="stat-label">Elapsed Time</span>
            </motion.div>
            <motion.div className="stat-card" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.7 }}>
              <Zap className="w-6 h-6 text-accent-orange" />
              <span className="stat-value">{stats.speed.toLocaleString()}</span>
              <span className="stat-label">Events/sec</span>
            </motion.div>
          </div>

          {/* Progress Bar */}
          <AnimatePresence>
            {isProcessing && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="glass-card p-4"
              >
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-dark-400">Processing...</span>
                  <span className="text-accent-cyan font-mono">{progress > 0 ? `${progress.toFixed(1)}%` : 'Scanning...'}</span>
                </div>
                <div className="progress-bar">
                  <motion.div
                    className="progress-fill"
                    initial={{ width: 0 }}
                    animate={{ width: progress > 0 ? `${progress}%` : '100%' }}
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Action Button */}
          <motion.div
            className="flex justify-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8 }}
          >
            {!isProcessing ? (
              <button onClick={startProcessing} disabled={!canStart} className="btn-primary px-12 py-4 text-lg flex items-center gap-3">
                <Play className="w-6 h-6" />
                Start Processing
              </button>
            ) : (
              <button onClick={stopProcessing} className="btn-danger px-12 py-4 text-lg flex items-center gap-3">
                <Square className="w-6 h-6" />
                Stop Processing
              </button>
            )}
          </motion.div>

        </div>
      </main>

      {/* Footer */}
      <footer className="flex-shrink-0 glass border-t border-dark-700/30 px-6 py-3">
        <div className="flex justify-between text-xs text-dark-500">
          <span>LogZero DFIR Timeline Generator</span>
          <span>High-performance forensic log processing</span>
        </div>
      </footer>

      {/* About Modal */}
      <AnimatePresence>
        {showAbout && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={() => setShowAbout(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="glass-card w-full max-w-4xl max-h-[80vh] overflow-hidden flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-5 border-b border-dark-700/50">
                <div className="flex items-center gap-3">
                  <div className="icon-box from-accent-blue to-accent-cyan">
                    <Zap className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-white">LogZero</h2>
                    <p className="text-xs text-dark-400">Supported Log Formats & Parsers</p>
                  </div>
                </div>
                <button
                  onClick={() => setShowAbout(false)}
                  className="p-2 rounded-lg hover:bg-dark-700/50 text-dark-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-y-auto p-5">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {parsers.map((category) => (
                    <div key={category.category} className="bg-dark-800/30 rounded-xl p-4 border border-dark-700/30">
                      <h3 className="text-sm font-semibold text-accent-cyan mb-3">{category.category}</h3>
                      <div className="space-y-2">
                        {category.items.map((parser) => (
                          <div key={parser.name} className="text-sm">
                            <div className="flex items-start justify-between gap-2">
                              <span className="text-dark-200 font-medium">{parser.name}</span>
                              <span className="text-xs text-dark-500 font-mono shrink-0">{parser.ext}</span>
                            </div>
                            <p className="text-xs text-dark-500 mt-0.5">{parser.desc}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Modal Footer */}
              <div className="p-4 border-t border-dark-700/50 bg-dark-900/50">
                <p className="text-xs text-dark-500 text-center">
                  LogZero automatically detects file types and applies the appropriate parser.
                  Unrecognized files are parsed using generic timestamp detection.
                </p>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default App
