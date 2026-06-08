import { usePolling } from './usePolling'
import { useStore } from '../store/useStore'
import {
  getCase, getCases, getSummary,
  getFindings, getDelta, getTimeline,
  getChainStatus, getIocs, getTodos, getReports,
  getPortalState,
} from '../api/endpoints'

export function useDataPolling() {
  const {
    setActiveCase, setCases, setSummary,
    setFindings, setDelta, setTimeline,
    setChainStatus, setLastSync, setIsLoading, setIocs, setTodos, setReports,
    setPortalState,
  } = useStore()

  usePolling(async () => {
    const [cas, cases, summary, findings, delta, timeline, chain, iocs, todos, reports, portal] = await Promise.allSettled([
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

    setLastSync(Date.now())
    setIsLoading(false)
  }, 15000)
}
