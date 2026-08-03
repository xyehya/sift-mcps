function extractDate(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.endsWith('Z') && ts.length >= 10) {
    return ts.substring(0, 10)
  }
  return new Date(ts).toISOString().substring(0, 10)
}

function extractTime(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.endsWith('Z') && ts.length >= 19) {
    return ts.substring(11, 19)
  }
  return new Date(ts).toISOString().substring(11, 19)
}

console.log(extractDate('2024-01-02T12:34:56Z'))
console.log(extractTime('2024-01-02T12:34:56Z'))
