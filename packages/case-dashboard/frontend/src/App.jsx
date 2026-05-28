import { useState, useEffect } from 'react'
import { useStore } from './store/useStore'
import { useDataPolling } from './hooks/useDataPolling'
import { onUnauthorized } from './api/client'
import { getMe } from './api/endpoints'
import { LoginCard } from './components/auth/LoginCard'
import { NavRail } from './components/layout/NavRail'
import { Header } from './components/layout/Header'
import { StatusBar } from './components/layout/StatusBar'
import { OverviewTab } from './components/overview/OverviewTab'
import { FindingsTab } from './components/findings/FindingsTab'
import { TimelineTab } from './components/timeline/TimelineTab'
import { EvidenceTab } from './components/evidence/EvidenceTab'
import { SettingsTab } from './components/settings/SettingsTab'
import { ReportsTab } from './components/reports/ReportsTab'
import { HostsTab } from './components/hosts/HostsTab'
import { Toaster } from './components/common/Toaster'
import { CommitDrawer } from './components/layout/CommitDrawer'

export default function App() {
  const { setUser, user } = useStore()
  const [authed, setAuthed] = useState(null) // null=checking, false=unauthed, true=authed
  const { activeTab } = useStore()

  useEffect(() => {
    getMe()
      .then((data) => {
        if (data) { setUser(data); setAuthed(true) }
        else setAuthed(false)
      })
      .catch(() => setAuthed(false))
  }, [])

  useEffect(() => {
    return onUnauthorized(() => setAuthed(false))
  }, [])

  function handleLogin(result) {
    setUser(result)
    setAuthed(true)
  }

  function handleLogout() {
    setUser(null)
    setAuthed(false)
  }

  if (authed === null) return null

  if (!authed) return <LoginCard onLogin={handleLogin} />

  return <AuthedApp onLogout={handleLogout} activeTab={activeTab} />
}

function AuthedApp({ onLogout, activeTab }) {
  useDataPolling()

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: 'var(--bg-base)' }}>
      <Header onLogout={onLogout} />
      <div className="flex flex-1 overflow-hidden">
        <NavRail />
        <main className="flex-1 overflow-hidden">
          {activeTab === 'overview'  && <OverviewTab />}
          {activeTab === 'findings'  && <FindingsTab />}
          {activeTab === 'timeline'  && <TimelineTab />}
          {activeTab === 'evidence'  && <EvidenceTab />}
          {activeTab === 'hosts'     && <HostsTab />}
          {activeTab === 'iocs'      && <PlaceholderTab label="IOCs" />}
          {activeTab === 'todos'     && <PlaceholderTab label="TODOs" />}
          {activeTab === 'reports'   && <ReportsTab />}
          {activeTab === 'settings'  && <SettingsTab />}
        </main>
      </div>
      <StatusBar />
      <CommitDrawer />
      <Toaster />
    </div>
  )
}

function PlaceholderTab({ label }) {
  return (
    <div className="flex items-center justify-center h-full" style={{ color: 'var(--text-muted)' }}>
      <p className="font-mono text-sm">{label} — coming soon</p>
    </div>
  )
}
