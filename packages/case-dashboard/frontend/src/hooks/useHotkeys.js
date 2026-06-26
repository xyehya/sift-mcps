import { useEffect } from 'react'

/**
 * useHotkey — bind a single keyboard shortcut to a handler for the lifetime of
 * the calling component. Ignores key events that originate from text inputs
 * (unless `allowInInput`) so shortcuts don't fire while the operator types.
 *
 * @param {object}   opts
 * @param {string}   opts.key            single key (case-insensitive), e.g. 'k'
 * @param {boolean} [opts.meta]          require ⌘ (mac) OR Ctrl (win/linux)
 * @param {boolean} [opts.shift]
 * @param {boolean} [opts.allowInInput]  fire even when focus is in a field
 * @param {(e: KeyboardEvent) => void} handler
 * @param {boolean} [enabled=true]       disable without unmounting
 */
export function useHotkey({ key, meta = false, shift = false, allowInInput = false }, handler, enabled = true) {
  useEffect(() => {
    if (!enabled) return undefined

    function onKeyDown(e) {
      if (e.key?.toLowerCase() !== key.toLowerCase()) return
      // meta:true matches ⌘ on mac and Ctrl elsewhere (the ⌘K convention).
      if (meta && !(e.metaKey || e.ctrlKey)) return
      if (!meta && (e.metaKey || e.ctrlKey)) return
      if (shift && !e.shiftKey) return

      if (!allowInInput) {
        const t = e.target
        const tag = t?.tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t?.isContentEditable) {
          return
        }
      }
      handler(e)
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [key, meta, shift, allowInInput, handler, enabled])
}
