'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Shield,
  AlertTriangle,
  Activity,
  TrendingUp,
  Search,
  Filter,
  RefreshCw,
  Zap,
  Clock,
  MapPin,
  Network,
  ArrowUpRight,
  ArrowDownRight,
  Download,
  FileText,
  Eye,
  CheckCircle,
  XCircle,
  Clock4,
  User,
  Target,
  Database,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  Bug,
  Globe,
  ShieldAlert,
  ArrowRight,
  BarChart3,
  Sun,
  Moon,
  Plus,
  Lock,
  ShieldOff,
  AlertOctagon,
  FileCheck,
} from 'lucide-react'

type Threat = {
  id: string
  title: string
  description: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  type: string
  status: string
  sourceIp: string | null
  destinationIp: string | null
  sourcePort: number | null
  destinationPort: number | null
  protocol: string | null
  isAnomaly: boolean
  anomalyScore: number | null
  confidence: number | null
  timestamp: string
  mitreTactics: string | null
  mitreTechniques: string | null
  assignedTo: string | null
  incidentId: string | null
  detectionMethod: string
  sourceSystem: string
  affectedHosts: string | null
  affectedUsers: string | null
  iocs?: IOC[]
  timelineEvents?: TimelineEvent[]
}

type IOC = {
  id: string
  type: string
  value: string
  description: string | null
  confidence: number | null
  source: string | null
  isActive: boolean
  firstSeen: string | null
  lastSeen: string | null
}

type TimelineEvent = {
  id: string
  eventType: string
  eventTime: string
  description: string
  userId: string | null
  source: string
}

type Analytics = {
  timeline: any[]
  summary: {
    totalThreats: number
    avgConfidence: number
    avgAnomalyScore: number
    activeInvestigations: number
    uniqueIocs: number
    resolutionRate: number
    mttr: number
    mttd: number
    activeIncidents: number
  }
  statusDistribution: any[]
  threatTypeDistribution: any[]
  detectionMethodDistribution: any[]
  iocDistribution: any[]
}

const severityColors = {
  LOW: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
  MEDIUM: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800',
  HIGH: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800',
  CRITICAL: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800',
}

const statusColors: Record<string, string> = {
  DETECTED: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800',
  INVESTIGATING: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800',
  CONTAINED: 'bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-200 dark:border-purple-800',
  RESOLVED: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
  FALSE_POSITIVE: 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-800',
  ESCALATED: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800',
  IN_PROGRESS: 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800',
  AWAITING_INFO: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800',
}

export default function ThreatHuntingDashboard() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [showFilters, setShowFilters] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>('dark')
  const [mounted, setMounted] = useState(false)
  const [selectedThreatIOCs, setSelectedThreatIOCs] = useState<IOC[]>([])
  const [selectedThreatTimeline, setSelectedThreatTimeline] = useState<TimelineEvent[]>([])
  const [users, setUsers] = useState<{ id: string, displayName: string, role: string }[]>([])

  // Load theme from localStorage on mount
  useEffect(() => {
    setMounted(true)
    const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null
    if (savedTheme) {
      setTheme(savedTheme)
      if (savedTheme === 'dark') {
        document.documentElement.classList.add('dark')
      } else {
        document.documentElement.classList.remove('dark')
      }
    }
  }, [])

  // Toggle theme
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light'
    setTheme(newTheme)
    localStorage.setItem('theme', newTheme)

    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }

  const [filters, setFilters] = useState({
    search: '',
    severity: 'all',
    type: 'all',
    status: 'all',
    isAnomaly: 'all',
    timeRange: '7d',
    assignedTo: '',
    hasIncident: 'all',
  })

  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  })

  const [actionDialog, setActionDialog] = useState({
    open: false,
    action: '',
    threatId: '',
  })

  const [actionData, setActionData] = useState({
    assignedToId: '',
    assignedTo: '',
    notes: '',
    remediation: '',
    status: '',
  })

  const fetchData = async (showLoading = true) => {
    try {
      if (showLoading) setLoading(true)

      const params = new URLSearchParams()
      Object.entries(filters).forEach(([key, value]) => {
        // Skip "all" values - they represent "no filter"
        if (value && value !== 'all') {
          params.append(key, value)
        }
      })
      params.append('page', pagination.page.toString())
      params.append('limit', pagination.limit.toString())

      const [threatsRes, analyticsRes] = await Promise.all([
        fetch(`/api/threats?${params}`),
        fetch('/api/analytics?days=30'),
      ])

      const threatsData = await threatsRes.json()
      const analyticsData = await analyticsRes.json()

      setThreats(threatsData.threats || [])
      setPagination(threatsData.pagination || pagination)
      setThreats(threatsData.threats || [])
      setPagination(threatsData.pagination || pagination)
      setAnalytics(analyticsData)

      // Fetch users if not already loaded
      if (users.length === 0) {
        fetch('/api/users')
          .then(res => res.json())
          .then(data => setUsers(data))
          .catch(err => console.error('Error fetching users:', err))
      }
      // Don't use new Date() - it causes hydration errors
    } catch (error) {
      console.error('Error fetching data:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchThreatDetails = async (threatId: string) => {
    try {
      const [iocsRes, timelineRes] = await Promise.all([
        fetch(`/api/iocs?threatId=${threatId}`),
        fetch(`/api/timeline?threatId=${threatId}`),
      ])

      const iocs = await iocsRes.json()
      const timeline = await timelineRes.json()

      setSelectedThreatIOCs(iocs || [])
      setSelectedThreatTimeline(timeline || [])
    } catch (error) {
      console.error('Error fetching threat details:', error)
    }
  }

  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!autoRefresh) return

    const interval = setInterval(() => {
      fetchData(false)
    }, 30000)

    return () => clearInterval(interval)
  }, [autoRefresh, filters, pagination.page])

  // Initial data fetch
  useEffect(() => {
    fetchData()
  }, [filters.severity, filters.type, filters.status, filters.isAnomaly, filters.timeRange, filters.assignedTo, filters.hasIncident, pagination.page])

  const filteredThreats = threats.filter(threat => {
    if (!filters.search) return true
    const searchLower = filters.search.toLowerCase()
    return (
      threat.title.toLowerCase().includes(searchLower) ||
      threat.description.toLowerCase().includes(searchLower) ||
      threat.sourceIp?.toLowerCase().includes(searchLower) ||
      threat.destinationIp?.toLowerCase().includes(searchLower) ||
      threat.affectedHosts?.toLowerCase().includes(searchLower) ||
      threat.affectedUsers?.toLowerCase().includes(searchLower) ||
      threat.incidentId?.toLowerCase().includes(searchLower)
    )
  })

  const runAnomalyDetection = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/anomaly', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: 'Suspicious Network Traffic Pattern Detected',
          description: 'Automated analysis detected unusual network traffic pattern. Multiple large outbound transfers to external IP during non-business hours. Pattern does not match normal user behavior and indicates potential data exfiltration activity.',
          type: 'SUSPICIOUS_BEHAVIOR',
          sourceIp: '192.168.1.200',
          destinationIp: '203.0.113.200',
          sourcePort: 50000,
          destinationPort: 443,
          protocol: 'HTTPS',
        }),
      })

      if (response.ok) {
        await fetchData()
      }
    } catch (error) {
      console.error('Error running anomaly detection:', error)
    } finally {
      setLoading(false)
    }
  }

  const performThreatAction = async () => {
    try {
      setLoading(true)

      // Build request body based on action type
      const requestBody: any = {
        action: actionDialog.action,
        ...actionData,
        [`${actionDialog.action}By`]: 'system', // In a real app, this would be the logged in user
        [`${actionDialog.action}By`]: 'SOC Analyst',
      }

      // Add additional data based on action type
      if (actionDialog.action === 'assign') {
        requestBody.status = 'INVESTIGATING'
      } else if (actionDialog.action === 'updateStatus') {
        if (actionData.status === 'RESOLVED') {
          requestBody.resolvedAt = new Date().toISOString()
          requestBody.resolvedBy = actionData.resolvedBy || 'SOC Analyst'
        }
      } else if (actionDialog.action === 'remediate') {
        requestBody.status = 'CONTAINED'
        requestBody.remediation = actionData.remediation
      } else if (actionDialog.action === 'addNote') {
        // Note is just added, no status change
      }

      const response = await fetch(`/api/threats/${actionDialog.threatId}/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      })

      if (response.ok) {
        // Show success message
        const actionMessage = `Successfully ${actionDialog.action === 'assign' ? 'assigned' :
          actionDialog.action === 'updateStatus' ? 'updated status' :
            actionDialog.action === 'addNote' ? 'added note to' :
              'remediated'} threat`

        // Refresh data and close dialog
        await fetchData()
        if (selectedThreat?.id === actionDialog.threatId) {
          await fetchThreatDetails(actionDialog.threatId)
        }
        setActionDialog({ open: false, action: '', threatId: '' })
        setActionData({ assignedTo: '', notes: '', remediation: '', status: '' })

        // Show toast notification
        console.log(actionMessage)
      } else {
        throw new Error(`Failed to perform action: ${response.statusText}`)
      }
    } catch (error) {
      console.error('Error performing action:', error)
      // Show error message
    } finally {
      setLoading(false)
    }
  }

  const exportData = async (format: 'json' | 'csv') => {
    try {
      const threatIds = filteredThreats.map(t => t.id).join(',')
      window.open(`/api/export?format=${format}&threatIds=${threatIds}`, '_blank')
    } catch (error) {
      console.error('Error exporting data:', error)
    }
  }

  const handleQuickAction = async (action: string) => {
    if (!selectedThreat) return

    try {
      setLoading(true)

      const response = await fetch(`/api/threats/${selectedThreat.id}/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          [`${action}By`]: 'SOC Analyst',
        }),
      })

      if (response.ok) {
        await fetchData()
        if (selectedThreat?.id === actionDialog.threatId) {
          await fetchThreatDetails(actionDialog.threatId)
        }
        console.log(`Successfully ${action}ed threat`)
      }
    } catch (error) {
      console.error(`Error ${action}ing threat:`, error)
    } finally {
      setLoading(false)
    }
  }

  const handleThreatSelect = async (threat: Threat) => {
    setSelectedThreat(threat)
    await fetchThreatDetails(threat.id)
  }

  const getSeverityCount = (severity: string) => {
    return threats.filter(t => t.severity === severity).length
  }

  const getStatusCount = (status: string) => {
    return threats.filter(t => t.status === status).length
  }

  // Prevent hydration mismatch by only rendering after mount
  if (!mounted) {
    return (
      <div className="min-h-screen bg-slate-50 dark:from-slate-950">
        <div className="flex items-center justify-center h-screen">
          <div className="text-slate-600 dark:text-slate-400">Loading...</div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-slate-100 to-slate-200 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      <div className="max-w-[1800px] mx-auto p-4 md:p-6 space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-red-500 to-orange-600 rounded-xl shadow-lg">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-red-600 to-orange-600 bg-clip-text text-transparent">
                Threat Hunting Dashboard
              </h1>
              <p className="text-slate-600 dark:text-slate-400 text-sm">Real-time Security Operations Center</p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowFilters(!showFilters)}
            >
              <Filter className="w-4 h-4 mr-2" />
              Filters
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => fetchData()}
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={toggleTheme}
              className="gap-2"
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="w-4 h-4" />
                  <span className="hidden sm:inline">Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4" />
                  <span className="hidden sm:inline">Dark</span>
                </>
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={autoRefresh ? 'bg-green-50 dark:bg-green-950/20' : ''}
            >
              <Activity className="w-4 h-4 mr-2" />
              Auto: {autoRefresh ? 'ON' : 'OFF'}
            </Button>

            <Button
              onClick={runAnomalyDetection}
              disabled={loading}
              className="bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-600 hover:to-orange-700"
              size="sm"
            >
              <Zap className="w-4 h-4 mr-2" />
              Run ML Detection
            </Button>

            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Download className="w-4 h-4 mr-2" />
                  Export
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Export Threat Data</DialogTitle>
                  <DialogDescription>Choose format for export</DialogDescription>
                </DialogHeader>
                <div className="flex gap-4 mt-4">
                  <Button onClick={() => exportData('json')} className="flex-1">
                    <FileText className="w-4 h-4 mr-2" />
                    JSON
                  </Button>
                  <Button onClick={() => exportData('csv')} className="flex-1" variant="outline">
                    <FileText className="w-4 h-4 mr-2" />
                    CSV
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        {analytics && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            <Card className="border-l-4 border-l-red-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  Critical
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                  {getSeverityCount('CRITICAL')}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-orange-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  High Severity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                  {getSeverityCount('HIGH')}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-purple-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  Anomalies
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                  {threats.filter(t => t.isAnomaly).length}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-amber-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  Investigating
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-amber-600 dark:text-amber-400">
                  {getStatusCount('INVESTIGATING')}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-emerald-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  Active Incidents
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">
                  {analytics.summary.activeIncidents}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-cyan-500 bg-white dark:bg-slate-900/50 backdrop-blur">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-slate-600 dark:text-slate-400">
                  MTTR (Hours)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-cyan-600 dark:text-cyan-400">
                  {analytics.summary.mttr.toFixed(1)}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Filters Panel */}
        {showFilters && (
          <Card className="bg-white dark:bg-slate-900/50 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Filter className="w-5 h-5" />
                Advanced Filters
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
                <div className="space-y-2">
                  <label className="text-xs font-medium">Search</label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <Input
                      placeholder="Search..."
                      value={filters.search}
                      onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                      className="pl-10 text-sm"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Time Range</label>
                  <Select value={filters.timeRange} onValueChange={(value) => setFilters({ ...filters, timeRange: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="24h">Last 24 Hours</SelectItem>
                      <SelectItem value="7d">Last 7 Days</SelectItem>
                      <SelectItem value="30d">Last 30 Days</SelectItem>
                      <SelectItem value="90d">Last 90 Days</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Severity</label>
                  <Select value={filters.severity} onValueChange={(value) => setFilters({ ...filters, severity: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="CRITICAL">Critical</SelectItem>
                      <SelectItem value="HIGH">High</SelectItem>
                      <SelectItem value="MEDIUM">Medium</SelectItem>
                      <SelectItem value="LOW">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Status</label>
                  <Select value={filters.status} onValueChange={(value) => setFilters({ ...filters, status: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Statuses</SelectItem>
                      <SelectItem value="DETECTED">Detected</SelectItem>
                      <SelectItem value="INVESTIGATING">Investigating</SelectItem>
                      <SelectItem value="CONTAINED">Contained</SelectItem>
                      <SelectItem value="RESOLVED">Resolved</SelectItem>
                      <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Type</label>
                  <Select value={filters.type} onValueChange={(value) => setFilters({ ...filters, type: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="MALWARE">Malware</SelectItem>
                      <SelectItem value="PHISHING">Phishing</SelectItem>
                      <SelectItem value="DDOS">DDoS</SelectItem>
                      <SelectItem value="INTRUSION">Intrusion</SelectItem>
                      <SelectItem value="DATA_EXFILTRATION">Data Exfiltration</SelectItem>
                      <SelectItem value="UNAUTHORIZED_ACCESS">Unauthorized Access</SelectItem>
                      <SelectItem value="LATERAL_MOVEMENT">Lateral Movement</SelectItem>
                      <SelectItem value="COMMAND_AND_CONTROL">C2 Communication</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Anomaly</label>
                  <Select value={filters.isAnomaly} onValueChange={(value) => setFilters({ ...filters, isAnomaly: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="true">Anomalies Only</SelectItem>
                      <SelectItem value="false">Non-Anomalies</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium">Incident</label>
                  <Select value={filters.hasIncident} onValueChange={(value) => setFilters({ ...filters, hasIncident: value })}>
                    <SelectTrigger className="text-sm">
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="true">Has Incident</SelectItem>
                      <SelectItem value="false">No Incident</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Threats List */}
          <div className="lg:col-span-2">
            <Card className="bg-white dark:bg-slate-900/50 backdrop-blur h-full">
              <CardHeader>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="w-5 h-5" />
                    Threat Activity ({pagination.total} total)
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px]">
                  {filteredThreats.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-slate-500">
                      <Shield className="w-16 h-16 mb-4 opacity-50" />
                      <p className="text-lg font-medium">No threats found</p>
                      <p className="text-sm">Try adjusting your filters</p>
                    </div>
                  ) : (
                    <>
                      <Table>
                        <TableHeader className="sticky top-0 bg-slate-50 dark:bg-slate-900 z-10">
                          <TableRow>
                            <TableHead className="w-[30%]">Threat</TableHead>
                            <TableHead className="w-[15%]">Severity</TableHead>
                            <TableHead className="w-[15%]">Status</TableHead>
                            <TableHead className="w-[25%]">Type</TableHead>
                            <TableHead className="w-[15%] text-right">Anomaly</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredThreats.map((threat) => (
                            <TableRow
                              key={threat.id}
                              onClick={() => handleThreatSelect(threat)}
                              className={`cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50
                                ${selectedThreat?.id === threat.id ? 'bg-slate-100 dark:bg-slate-800' : ''}
                              `}
                            >
                              <TableCell>
                                <div className="space-y-1">
                                  <div className="font-medium text-sm">{threat.title}</div>
                                  <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                                    <Clock className="w-3 h-3" />
                                    {new Date(threat.timestamp).toLocaleString()}
                                  </div>
                                  {threat.incidentId && (
                                    <Badge variant="outline" className="text-xs mt-1">
                                      {threat.incidentId}
                                    </Badge>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge className={`${severityColors[threat.severity]} text-xs`}>
                                  {threat.severity}
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <Badge className={`${statusColors[threat.status] || ''} text-xs`}>
                                  {threat.status.replace(/_/g, ' ')}
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <div className="flex items-center gap-2 flex-wrap">
                                  {threat.isAnomaly && (
                                    <Zap className="w-3 h-3 text-purple-500" />
                                  )}
                                  <span className="text-xs">{threat.type.replace(/_/g, ' ')}</span>
                                </div>
                              </TableCell>
                              <TableCell className="text-right">
                                {threat.anomalyScore !== null ? (
                                  <div className="text-right">
                                    <div className="font-medium text-purple-600 dark:text-purple-400 text-sm">
                                      {(threat.anomalyScore * 100).toFixed(0)}%
                                    </div>
                                    {threat.confidence !== null && (
                                      <div className="text-xs text-slate-500">
                                        {(threat.confidence * 100).toFixed(0)}% conf.
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  <span className="text-slate-400 text-sm">—</span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>

                      {/* Pagination */}
                      {pagination.totalPages > 1 && (
                        <div className="flex items-center justify-between mt-4 pt-4 border-t">
                          <div className="text-sm text-slate-600 dark:text-slate-400">
                            Showing {((pagination.page - 1) * pagination.limit) + 1} to {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total}
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setPagination({ ...pagination, page: pagination.page - 1 })}
                              disabled={pagination.page === 1}
                            >
                              <ChevronLeft className="w-4 h-4" />
                            </Button>
                            <span className="text-sm">
                              Page {pagination.page} of {pagination.totalPages}
                            </span>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setPagination({ ...pagination, page: pagination.page + 1 })}
                              disabled={pagination.page === pagination.totalPages}
                            >
                              <ChevronRight className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {/* Threat Details */}
          <div className="lg:col-span-1">
            <Card className="bg-white dark:bg-slate-900/50 backdrop-blur h-full">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Threat Details
                </CardTitle>
              </CardHeader>
              <CardContent>
                {selectedThreat ? (
                  <ScrollArea className="h-[600px] pr-4">
                    <Tabs defaultValue="overview" className="w-full">
                      <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="overview">Overview</TabsTrigger>
                        <TabsTrigger value="iocs">IOCs</TabsTrigger>
                        <TabsTrigger value="timeline">Timeline</TabsTrigger>
                      </TabsList>

                      <TabsContent value="overview" className="space-y-4 mt-4">
                        {/* Title and Badges */}
                        <div>
                          <h3 className="text-lg font-semibold mb-2">{selectedThreat.title}</h3>
                          <div className="flex gap-2 flex-wrap">
                            <Badge className={severityColors[selectedThreat.severity]}>
                              {selectedThreat.severity}
                            </Badge>
                            <Badge className={statusColors[selectedThreat.status] || ''}>
                              {selectedThreat.status.replace(/_/g, ' ')}
                            </Badge>
                            {selectedThreat.isAnomaly && (
                              <Badge variant="outline" className="bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-200 dark:border-purple-800">
                                <Zap className="w-3 h-3 mr-1" />
                                Anomaly
                              </Badge>
                            )}
                          </div>
                        </div>

                        <Separator />

                        {/* Description */}
                        <div>
                          <h4 className="text-sm font-medium mb-2 text-slate-700 dark:text-slate-300">Description</h4>
                          <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                            {selectedThreat.description}
                          </p>
                        </div>

                        <Separator />

                        {/* Network Details */}
                        <div className="space-y-3">
                          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">Network Details</h4>

                          {selectedThreat.sourceIp && (
                            <div className="flex items-center gap-2 text-sm">
                              <ArrowUpRight className="w-4 h-4 text-red-500" />
                              <span className="text-slate-600 dark:text-slate-400">Source:</span>
                              <code className="bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded font-mono text-xs">
                                {selectedThreat.sourceIp}:{selectedThreat.sourcePort || '—'}
                              </code>
                            </div>
                          )}

                          {selectedThreat.destinationIp && (
                            <div className="flex items-center gap-2 text-sm">
                              <ArrowDownRight className="w-4 h-4 text-emerald-500" />
                              <span className="text-slate-600 dark:text-slate-400">Destination:</span>
                              <code className="bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded font-mono text-xs">
                                {selectedThreat.destinationIp}:{selectedThreat.destinationPort || '—'}
                              </code>
                            </div>
                          )}

                          {selectedThreat.protocol && (
                            <div className="flex items-center gap-2 text-sm">
                              <Network className="w-4 h-4 text-slate-400" />
                              <Badge variant="outline">{selectedThreat.protocol}</Badge>
                            </div>
                          )}
                        </div>

                        <Separator />

                        {/* Affected Assets */}
                        {(selectedThreat.affectedHosts || selectedThreat.affectedUsers) && (
                          <div className="space-y-2">
                            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">Affected Assets</h4>
                            {selectedThreat.affectedHosts && (
                              <div className="flex items-start gap-2 text-sm">
                                <Database className="w-4 h-4 text-orange-500 mt-0.5" />
                                <span className="text-slate-600 dark:text-slate-400">{selectedThreat.affectedHosts}</span>
                              </div>
                            )}
                            {selectedThreat.affectedUsers && (
                              <div className="flex items-start gap-2 text-sm">
                                <User className="w-4 h-4 text-blue-500 mt-0.5" />
                                <span className="text-slate-600 dark:text-slate-400">{selectedThreat.affectedUsers}</span>
                              </div>
                            )}
                          </div>
                        )}

                        <Separator />

                        {/* MITRE ATT&CK */}
                        {(selectedThreat.mitreTactics || selectedThreat.mitreTechniques) && (
                          <div className="space-y-2">
                            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">MITRE ATT&CK</h4>

                            {selectedThreat.mitreTactics && (
                              <div>
                                <span className="text-xs text-slate-500 dark:text-slate-400">Tactics:</span>
                                <div className="flex gap-1 flex-wrap mt-1">
                                  {selectedThreat.mitreTactics.split(', ').map((tactic, i) => (
                                    <Badge key={i} variant="outline" className="text-xs">
                                      {tactic}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}

                            {selectedThreat.mitreTechniques && (
                              <div>
                                <span className="text-xs text-slate-500 dark:text-slate-400">Techniques:</span>
                                <div className="flex gap-1 flex-wrap mt-1">
                                  {selectedThreat.mitreTechniques.split(', ').map((tech, i) => (
                                    <Badge key={i} variant="outline" className="text-xs">
                                      {tech}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}

                        <Separator />

                        {/* Detection Info */}
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">Detection Information</h4>
                          <div className="text-sm space-y-1">
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-400">Method:</span>
                              <span className="text-slate-700 dark:text-slate-300">{selectedThreat.detectionMethod}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500 dark:text-slate-400">Source:</span>
                              <span className="text-slate-700 dark:text-slate-300">{selectedThreat.sourceSystem}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Clock className="w-4 h-4 text-slate-400" />
                              <span className="text-slate-600 dark:text-slate-400">
                                {new Date(selectedThreat.timestamp).toLocaleString()}
                              </span>
                            </div>
                          </div>
                        </div>

                        <Separator />

                        {/* Assignment */}
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">Assignment</h4>
                          {selectedThreat.assignedTo ? (
                            <div className="flex items-center gap-2 text-sm">
                              <User className="w-4 h-4 text-blue-500" />
                              <span className="text-slate-700 dark:text-slate-300">{selectedThreat.assignedTo}</span>
                            </div>
                          ) : (
                            <span className="text-sm text-slate-500 dark:text-slate-400">Not assigned</span>
                          )}
                        </div>

                        <Separator />

                        {/* Actions */}
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">Quick Actions</h4>
                          <div className="flex flex-col gap-2">
                            <Dialog open={actionDialog.open && actionDialog.action === 'assign'} onOpenChange={(open) => setActionDialog({ ...actionDialog, open })}>
                              <DialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="w-full justify-start"
                                  onClick={() => {
                                    setActionDialog({ open: true, action: 'assign', threatId: selectedThreat.id })
                                    setActionData({ ...actionData, assignedTo: selectedThreat.assignedTo || '' })
                                  }}
                                >
                                  <User className="w-4 h-4 mr-2" />
                                  Assign Analyst
                                </Button>
                              </DialogTrigger>
                              <DialogContent>
                                <DialogHeader>
                                  <DialogTitle>Assign Threat</DialogTitle>
                                  <DialogDescription>Assign this threat to an analyst</DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4 mt-4">
                                  <div>
                                    <Label>Assigned To</Label>
                                    <Select
                                      value={actionData.assignedToId}
                                      onValueChange={(value) => {
                                        const user = users.find(u => u.id === value)
                                        setActionData({
                                          ...actionData,
                                          assignedToId: value,
                                          assignedTo: user?.displayName || ''
                                        })
                                      }}
                                    >
                                      <SelectTrigger>
                                        <SelectValue placeholder="Select analyst" />
                                      </SelectTrigger>
                                      <SelectContent>
                                        {users.map((user) => (
                                          <SelectItem key={user.id} value={user.id}>
                                            {user.displayName} ({user.role.replace(/_/g, ' ')})
                                          </SelectItem>
                                        ))}
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  <Button onClick={performThreatAction} disabled={!actionData.assignedToId}>
                                    Assign
                                  </Button>
                                </div>
                              </DialogContent>
                            </Dialog>

                            <Dialog open={actionDialog.open && actionDialog.action === 'updateStatus'} onOpenChange={(open) => setActionDialog({ ...actionDialog, open })}>
                              <DialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="w-full justify-start"
                                  onClick={() => {
                                    setActionDialog({ open: true, action: 'updateStatus', threatId: selectedThreat.id })
                                    setActionData({ ...actionData, status: selectedThreat.status })
                                  }}
                                >
                                  <CheckCircle className="w-4 h-4 mr-2" />
                                  Update Status
                                </Button>
                              </DialogTrigger>
                              <DialogContent>
                                <DialogHeader>
                                  <DialogTitle>Update Threat Status</DialogTitle>
                                  <DialogDescription>Change the status of this threat</DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4 mt-4">
                                  <div>
                                    <Label>New Status</Label>
                                    <Select value={actionData.status} onValueChange={(value) => setActionData({ ...actionData, status: value })}>
                                      <SelectTrigger>
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value="INVESTIGATING">Investigating</SelectItem>
                                        <SelectItem value="CONTAINED">Contained</SelectItem>
                                        <SelectItem value="RESOLVED">Resolved</SelectItem>
                                        <SelectItem value="DETECTED">Detected</SelectItem>
                                        <SelectItem value="INVESTIGATING">Investigating</SelectItem>
                                        <SelectItem value="IN_PROGRESS">In Progress</SelectItem>
                                        <SelectItem value="CONTAINED">Contained</SelectItem>
                                        <SelectItem value="RESOLVED">Resolved</SelectItem>
                                        <SelectItem value="CLOSED">Closed</SelectItem>
                                        <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
                                        <SelectItem value="ESCALATED">Escalated</SelectItem>
                                        <SelectItem value="AWAITING_INFO">Awaiting Info</SelectItem>
                                        <SelectItem value="MONITORING">Monitoring</SelectItem>
                                        <SelectItem value="DEFERRED">Deferred</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  <Button onClick={performThreatAction} disabled={!actionData.status}>
                                    Update Status
                                  </Button>
                                </div>
                              </DialogContent>
                            </Dialog>

                            <Dialog open={actionDialog.open && actionDialog.action === 'addNote'} onOpenChange={(open) => setActionDialog({ ...actionDialog, open })}>
                              <DialogTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="w-full justify-start"
                                  onClick={() => {
                                    setActionDialog({ open: true, action: 'addNote', threatId: selectedThreat.id })
                                  }}
                                >
                                  <FileText className="w-4 h-4 mr-2" />
                                  Add Note
                                </Button>
                              </DialogTrigger>
                              <DialogContent>
                                <DialogHeader>
                                  <DialogTitle>Add Note</DialogTitle>
                                  <DialogDescription>Add investigation notes to this threat</DialogDescription>
                                </DialogHeader>
                                <div className="space-y-4 mt-4">
                                  <div>
                                    <Label>Note</Label>
                                    <Textarea
                                      value={actionData.notes}
                                      onChange={(e) => setActionData({ ...actionData, notes: e.target.value })}
                                      placeholder="Enter your notes..."
                                      rows={4}
                                    />
                                  </div>
                                  <Button onClick={performThreatAction} disabled={!actionData.notes}>
                                    Add Note
                                  </Button>
                                </div>
                              </DialogContent>
                            </Dialog>
                          </div>
                        </div>

                        {/* Anomaly Score */}
                        {selectedThreat.anomalyScore !== null && (
                          <Alert className="bg-purple-50 dark:bg-purple-950/20 border-purple-200 dark:border-purple-800">
                            <Zap className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                            <AlertDescription className="text-sm">
                              <div className="font-medium text-purple-900 dark:text-purple-100 mb-1">
                                ML Anomaly Score: {(selectedThreat.anomalyScore * 100).toFixed(0)}%
                              </div>
                              <div className="text-purple-700 dark:text-purple-300">
                                {selectedThreat.confidence && (
                                  <>Confidence: {(selectedThreat.confidence * 100).toFixed(0)}% • </>
                                )}
                                AI-powered detection
                              </div>
                            </AlertDescription>
                          </Alert>
                        )}
                      </TabsContent>

                      <TabsContent value="iocs" className="space-y-4 mt-4">
                        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">
                          Indicators of Compromise ({selectedThreatIOCs.length})
                        </h4>
                        {selectedThreatIOCs.length === 0 ? (
                          <p className="text-sm text-slate-500 dark:text-slate-400">No IOCs found for this threat</p>
                        ) : (
                          <div className="space-y-2">
                            {selectedThreatIOCs.map((ioc) => (
                              <Card key={ioc.id} className="p-3">
                                <div className="flex items-start justify-between gap-2">
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                      <Badge variant="outline" className="text-xs">
                                        {ioc.type.replace(/_/g, ' ')}
                                      </Badge>
                                      {ioc.isActive ? (
                                        <Badge variant="outline" className="text-xs bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800">
                                          Active
                                        </Badge>
                                      ) : (
                                        <Badge variant="outline" className="text-xs bg-slate-50 dark:bg-slate-950/20 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-800">
                                          Inactive
                                        </Badge>
                                      )}
                                    </div>
                                    <code className="text-xs bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded block break-all">
                                      {ioc.value}
                                    </code>
                                    {ioc.description && (
                                      <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                                        {ioc.description}
                                      </p>
                                    )}
                                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500 dark:text-slate-400">
                                      {ioc.confidence && (
                                        <span>Confidence: {(ioc.confidence * 100).toFixed(0)}%</span>
                                      )}
                                      {ioc.source && (
                                        <span>Source: {ioc.source}</span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </Card>
                            ))}
                          </div>
                        )}
                      </TabsContent>

                      <TabsContent value="timeline" className="space-y-4 mt-4">
                        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">
                          Event Timeline ({selectedThreatTimeline.length})
                        </h4>
                        {selectedThreatTimeline.length === 0 ? (
                          <p className="text-sm text-slate-500 dark:text-slate-400">No timeline events found</p>
                        ) : (
                          <div className="space-y-3">
                            {selectedThreatTimeline.map((event, index) => (
                              <div key={event.id} className="flex gap-3">
                                <div className="flex flex-col items-center">
                                  <div className={`w-3 h-3 rounded-full ${index === 0 ? 'bg-red-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
                                  {index < selectedThreatTimeline.length - 1 && (
                                    <div className="w-0.5 flex-1 bg-slate-200 dark:bg-slate-700" />
                                  )}
                                </div>
                                <Card className="flex-1 p-3">
                                  <div className="flex items-center justify-between mb-1">
                                    <Badge variant="outline" className="text-xs">
                                      {event.eventType}
                                    </Badge>
                                    <span className="text-xs text-slate-500 dark:text-slate-400">
                                      {new Date(event.eventTime).toLocaleString()}
                                    </span>
                                  </div>
                                  <p className="text-sm text-slate-700 dark:text-slate-300">
                                    {event.description}
                                  </p>
                                  {event.userId && (
                                    <div className="flex items-center gap-1 mt-2 text-xs text-slate-500 dark:text-slate-400">
                                      <User className="w-3 h-3" />
                                      {event.userId}
                                    </div>
                                  )}
                                </Card>
                              </div>
                            ))}
                          </div>
                        )}
                      </TabsContent>
                    </Tabs>
                  </ScrollArea>
                ) : (
                  <div className="flex flex-col items-center justify-center h-[600px] text-slate-500">
                    <Shield className="w-16 h-16 mb-4 opacity-50" />
                    <p className="text-lg font-medium">Select a threat</p>
                    <p className="text-sm">Click on a threat to view details</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Footer */}
        <footer className="text-center text-sm text-slate-500 dark:text-slate-400 py-4 border-t border-slate-200 dark:border-slate-800">
          <p>Threat Hunting Dashboard • ML-Powered Anomaly Detection • MITRE ATT&CK Framework • Real-time Monitoring</p>
        </footer>
      </div>
    </div>
  )
}
