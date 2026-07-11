import { performance } from 'node:perf_hooks'

import { parseTimestamp } from '../src/lib/timestamp-utils.js'

const ROW_COUNT = Number.parseInt(process.env.TIMESTAMP_BENCH_ROWS ?? '10000', 10)
const ITERATIONS = Number.parseInt(process.env.TIMESTAMP_BENCH_ITERATIONS ?? '50', 10)

if (!Number.isSafeInteger(ROW_COUNT) || ROW_COUNT < 1 || !Number.isSafeInteger(ITERATIONS) || ITERATIONS < 1) {
  throw new Error('TIMESTAMP_BENCH_ROWS and TIMESTAMP_BENCH_ITERATIONS must be positive integers')
}

const base = Date.parse('2026-01-01T00:00:00.000Z')
const timestamps = Array.from({ length: ROW_COUNT }, (_, index) => new Date(base + ((index * 7919) % ROW_COUNT) * 1000).toISOString())

function measure(name, parse) {
  let checksum = 0
  const started = performance.now()
  for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
    const sorted = timestamps.slice().sort((left, right) => parse(left) - parse(right))
    checksum += parse(sorted[0]) + parse(sorted.at(-1))
  }
  const elapsedMs = performance.now() - started
  console.log(`${name}: ${elapsedMs.toFixed(2)}ms (${ROW_COUNT} rows × ${ITERATIONS} iterations, checksum ${checksum})`)
}

measure('Date.parse', parseTimestamp)
measure('new Date().getTime', (value) => new Date(value).getTime())
