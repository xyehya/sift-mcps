// PBKDF2 + HMAC-SHA256 challenge-response — matches server-side auth.py

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  return bytes
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => ('0' + b.toString(16)).slice(-2)).join('')
}

export async function computeChallengeResponse(password, challenge) {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const salt = hexToBytes(challenge.salt)
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: challenge.iterations, hash: challenge.hash_algorithm },
    keyMaterial, 256
  )
  const domainKey = await crypto.subtle.importKey('raw', derivedBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const authBits = await crypto.subtle.sign('HMAC', domainKey, enc.encode('sift-auth-v1'))
  const hmacKey = await crypto.subtle.importKey('raw', authBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(challenge.nonce))
  return bytesToHex(new Uint8Array(sig))
}

// Used for case activation and commit (no 'sift-auth-v1' domain step)
export async function computeSimpleChallengeResponse(password, challenge) {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const salt = hexToBytes(challenge.salt)
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: challenge.iterations, hash: challenge.hash_algorithm },
    keyMaterial, 256
  )
  const hmacKey = await crypto.subtle.importKey('raw', derivedBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(challenge.nonce))
  return bytesToHex(new Uint8Array(sig))
}
