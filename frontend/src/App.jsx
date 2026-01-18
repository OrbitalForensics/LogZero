import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FolderOpen, FileOutput, Play, Square, Trash2, Settings,
  Activity, Clock, Files, Zap, Terminal, ChevronRight,
  CheckCircle, AlertTriangle, Info, X
} from 'lucide-react'
import { AreaChart, Area, ResponsiveContainer, Tooltip } from 'recharts'

// Wails runtime - will be available when running in Wails
const runtime = window.runtime
const go = window.go

function App() {
  const [inputPath, setInputPath] = useState('')
  const [outputPath, setOutputPath] = useState('')
  const [format, setFormat] = useState('jsonl')
  const [isProcessing, setIsProcessing] = useState(false)
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState({ files: 0, events: 0, elapsed: '00:00', speed: 0 })
  const [chartData, setChartData] = useState([])
  const [progress, setProgress] = useState(0)
  const logEndRef = useRef(null)
  const startTimeRef = useRef(null)

  const formats = [
    { id: 'jsonl', name: 'JSONL', desc: 'JSON Lines - Best for analysis tools' },
    { id: 'csv', name: 'CSV', desc: 'Spreadsheet compatible format' },
    { id: 'sqlite', name: 'SQLite', desc: 'Database for complex queries' },
  ]

  useEffect(() => {
    if (!runtime) return

    runtime.EventsOn('log', (msg) => addLog(msg, 'info'))
    runtime.EventsOn('error', (msg) => addLog(msg, 'error'))
    runtime.EventsOn('warning', (msg) => addLog(msg, 'warning'))

    runtime.EventsOn('progress', (data) => {
      setStats(s => ({ ...s, files: data.files, events: data.events }))
      setProgress(data.percent || 0)
      setChartData(prev => [...prev.slice(-50), { time: Date.now(), events: data.events }])
    })

    runtime.EventsOn('complete', () => {
      setIsProcessing(false)
      addLog('Processing completed successfully!', 'success')
    })

    return () => {
      runtime.EventsOff('log')
      runtime.EventsOff('error')
      runtime.EventsOff('warning')
      runtime.EventsOff('progress')
      runtime.EventsOff('complete')
    }
  }, [])

  useEffect(() => {
    let interval
    if (isProcessing && startTimeRef.current) {
      interval = setInterval(() => {
        const elapsed = Date.now() - startTimeRef.current
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
  }, [isProcessing, stats.events])

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const addLog = (message, type = 'info') => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false })
    setLogs(prev => [...prev.slice(-300), { message, type, time }])
  }

  const selectInput = async () => {
    if (!go) return setInputPath('/demo/logs')
    try {
      const path = await go.main.App.SelectInputFolder()
      if (path) {
        setInputPath(path)
        addLog(`Selected input: ${path}`)
      }
    } catch (e) {
      addLog(`Error: ${e}`, 'error')
    }
  }

  const selectOutput = async () => {
    if (!go) return setOutputPath('/demo/output.jsonl')
    try {
      const path = await go.main.App.SelectOutputFile(format)
      if (path) {
        setOutputPath(path)
        addLog(`Selected output: ${path}`)
      }
    } catch (e) {
      addLog(`Error: ${e}`, 'error')
    }
  }

  const startProcessing = async () => {
    if (!inputPath || !outputPath) {
      addLog('Please select input and output paths', 'warning')
      return
    }

    setIsProcessing(true)
    setStats({ files: 0, events: 0, elapsed: '00:00', speed: 0 })
    setProgress(0)
    setChartData([])
    startTimeRef.current = Date.now()

    addLog('Starting processing...')
    addLog(`Input: ${inputPath}`)
    addLog(`Output: ${outputPath}`)
    addLog(`Format: ${format.toUpperCase()}`)

    if (go) {
      try {
        await go.main.App.StartProcessing(inputPath, outputPath, format)
      } catch (e) {
        addLog(`Error: ${e}`, 'error')
        setIsProcessing(false)
      }
    }
  }

  const stopProcessing = async () => {
    if (go) {
      try {
        await go.main.App.StopProcessing()
      } catch (e) {
        addLog(`Error stopping: ${e}`, 'error')
      }
    }
    setIsProcessing(false)
    addLog('Processing stopped', 'warning')
  }

  const canStart = inputPath && outputPath && !isProcessing

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
                  <FolderOpen className="w-5 h-5 text-white" />
                </div>
                <span>Input Source</span>
              </div>
              <button
                onClick={selectInput}
                disabled={isProcessing}
                className="w-full btn-ghost text-left flex items-center justify-between group"
              >
                <span>Select Folder</span>
                <ChevronRight className="w-4 h-4 text-dark-500 group-hover:text-white transition-colors" />
              </button>
              <AnimatePresence>
                {inputPath && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-3 p-3 bg-dark-800/50 rounded-lg border border-dark-700/30"
                  >
                    <p className="text-xs text-dark-400 mb-1">Selected:</p>
                    <p className="text-sm font-mono text-accent-cyan truncate">{inputPath}</p>
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
                <span>Output File</span>
              </div>
              <button
                onClick={selectOutput}
                disabled={isProcessing}
                className="w-full btn-ghost text-left flex items-center justify-between group"
              >
                <span>Select File</span>
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

          {/* Chart & Log Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Chart */}
            <motion.div
              className="glass-card p-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.9 }}
            >
              <div className="section-header mb-4">
                <div className="icon-box from-accent-green to-teal-600">
                  <Activity className="w-5 h-5 text-white" />
                </div>
                <span>Real-time Activity</span>
              </div>
              <div className="h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Tooltip
                      contentStyle={{ background: '#202123', border: '1px solid #40414f', borderRadius: '8px' }}
                      labelStyle={{ color: '#8e8ea0' }}
                      itemStyle={{ color: '#3b82f6' }}
                    />
                    <Area type="monotone" dataKey="events" stroke="#3b82f6" strokeWidth={2} fill="url(#colorEvents)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </motion.div>

            {/* Log */}
            <motion.div
              className="glass-card p-5"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.0 }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="section-header">
                  <div className="icon-box from-dark-600 to-dark-700">
                    <Terminal className="w-5 h-5 text-accent-green" />
                  </div>
                  <span>System Log</span>
                </div>
                <button onClick={() => setLogs([])} className="p-2 text-dark-500 hover:text-white transition-colors rounded-lg hover:bg-dark-700/50">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
              <div className="terminal h-44 overflow-y-auto">
                {logs.length === 0 ? (
                  <p className="text-dark-500 italic">Awaiting commands...</p>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className={`py-0.5 flex gap-2 ${
                      log.type === 'error' ? 'text-accent-red' :
                      log.type === 'warning' ? 'text-accent-orange' :
                      log.type === 'success' ? 'text-accent-green' :
                      'text-dark-300'
                    }`}>
                      <span className="text-dark-600 shrink-0">[{log.time}]</span>
                      <span>{log.message}</span>
                    </div>
                  ))
                )}
                <div ref={logEndRef} />
              </div>
            </motion.div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="flex-shrink-0 glass border-t border-dark-700/30 px-6 py-3">
        <div className="flex justify-between text-xs text-dark-500">
          <span>LogZero DFIR Timeline Generator</span>
          <span>High-performance forensic log processing</span>
        </div>
      </footer>
    </div>
  )
}

export default App
