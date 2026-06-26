import { usePolling } from './usePolling'
import { useStoreSlice } from '../store/useStore'
import {
  getCase, getCases, getSummary,
  getFindings, getDelta, getTimeline,
  getChainStatus, getIocs, getTodos, getReports,
  getPortalState, getAgentActivity,
} from '../api/endpoints'

export function useDataPolling() {
  const {
    setActiveCase, setCases, setSummary,
    setFindings, setDelta, setTimeline,
    setChainStatus, setLastSync, setIsLoading, setIocs, setTodos, setReports,
    setPortalState, setAgentActivity,
  } = useStoreSlice((state) => ({
    setActiveCase: state.setActiveCase,
    setCases: state.setCases,
    setSummary: state.setSummary,
    setFindings: state.setFindings,
    setDelta: state.setDelta,
    setTimeline: state.setTimeline,
    setChainStatus: state.setChainStatus,
    setLastSync: state.setLastSync,
    setIsLoading: state.setIsLoading,
    setIocs: state.setIocs,
    setTodos: state.setTodos,
    setReports: state.setReports,
    setPortalState: state.setPortalState,
    setAgentActivity: state.setAgentActivity,
  }))

  usePolling(async () => {
    // DEV-only: when seeded with mock fixtures (?mock), skip the poll so it
    // doesn't overwrite them. The flag is never set in prod/tests.
    if (typeof window !== 'undefined' && window.__SIFT_MOCK__) return
    const [
      cas,
      cases,
      summary,
      findings,
      delta,
      timeline,
      chain,
      iocs,
      todos,
      reports,
      portal,
      agentActivity,
    ] = await Promise.allSettled([
      getCase(),
      getCases(),
      getSummary(),
      getFindings(),
      getDelta(),
      getTimeline(),
      getChainStatus(),
      getIocs(),
      getTodos(),
      getReports(),
      getPortalState(),
      getAgentActivity(),
    ])

    if (cas.status === 'fulfilled' && cas.value) setActiveCase(cas.value)
    if (cases.status === 'fulfilled' && cases.value) setCases(cases.value?.cases ?? [])
    if (summary.status === 'fulfilled' && summary.value) setSummary(summary.value)
    if (findings.status === 'fulfilled' && findings.value) setFindings(findings.value)
    if (delta.status === 'fulfilled' && delta.value) setDelta(delta.value.items ?? [])
    if (timeline.status === 'fulfilled' && timeline.value) setTimeline(timeline.value)
    if (chain.status === 'fulfilled' && chain.value) setChainStatus(chain.value)
    if (iocs.status === 'fulfilled' && iocs.value) setIocs(iocs.value)
    if (todos.status === 'fulfilled' && todos.value) setTodos(todos.value)
    if (reports.status === 'fulfilled' && reports.value) setReports(reports.value)
    if (portal.status === 'fulfilled' && portal.value) setPortalState(portal.value)
    if (agentActivity.status === 'fulfilled' && agentActivity.value) {
      setAgentActivity(agentActivity.value?.events ?? [])
    }

    setLastSync(Date.now())
    setIsLoading(false)
  }, 15000)
}
