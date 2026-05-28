import { usePolling } from './usePolling'
import { useStore } from '../store/useStore'
import {
  getCase, getCases, getSummary,
  getFindings, getDelta, getTimeline,
  getChainStatus,
} from '../api/endpoints'

export function useDataPolling() {
  const {
    setActiveCase, setCases, setSummary,
    setFindings, setDelta, setTimeline,
    setChainStatus, setLastSync, setIsLoading,
  } = useStore()

  usePolling(async () => {
    const [cas, cases, summary, findings, delta, timeline, chain] = await Promise.allSettled([
      getCase(),
      getCases(),
      getSummary(),
      getFindings(),
      getDelta(),
      getTimeline(),
      getChainStatus(),
    ])

    if (cas.status === 'fulfilled' && cas.value) setActiveCase(cas.value)
    if (cases.status === 'fulfilled' && cases.value) setCases(cases.value)
    if (summary.status === 'fulfilled' && summary.value) setSummary(summary.value)
    if (findings.status === 'fulfilled' && findings.value) setFindings(findings.value)
    if (delta.status === 'fulfilled' && delta.value) setDelta(delta.value.items ?? [])
    if (timeline.status === 'fulfilled' && timeline.value) setTimeline(timeline.value)
    if (chain.status === 'fulfilled' && chain.value) setChainStatus(chain.value)

    setLastSync(Date.now())
    setIsLoading(false)
  }, 15000)
}
