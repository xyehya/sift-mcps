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
import { AccountsTab } from './components/accounts/AccountsTab'
import { IocsTab } from './components/iocs/IocsTab'
import { TodosTab } from './components/todos/TodosTab'
import { BackendsTab } from './components/backends/BackendsTab'
import { Toaster } from './components/common/Toaster'
import { CommitDrawer } from './components/layout/CommitDrawer'
import { CommandPalette } from './components/layout/CommandPalette'

export default function App() {
  const setUser = useStore((state) => state.setUser)
  const [authed, setAuthed] = useState(null) // null=checking, false=unauthed, true=authed
  const activeTab = useStore((state) => state.activeTab)

  useEffect(() => {
    getMe()
      .then((data) => {
        if (data) { setUser(data); setAuthed(true) }
        else setAuthed(false)
      })
      .catch(() => setAuthed(false))
  }, [setUser])

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
  const setCommandPaletteOpen = useStore((state) => state.setCommandPaletteOpen)
  useDataPolling()

  // Ctrl+K / Cmd+K → toggle command palette
  useEffect(() => {
    function onKeyDown(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setCommandPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [setCommandPaletteOpen])

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
          {activeTab === 'accounts'  && <AccountsTab />}
          {activeTab === 'iocs'      && <IocsTab />}
          {activeTab === 'todos'     && <TodosTab />}
          {activeTab === 'backends'  && <BackendsTab />}
          {activeTab === 'reports'   && <ReportsTab />}
          {activeTab === 'settings'  && <SettingsTab />}
        </main>
      </div>
      <StatusBar />
      <CommitDrawer />
      <CommandPalette />
      <Toaster />
    </div>
  )
}
