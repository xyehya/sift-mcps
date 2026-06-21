import '@testing-library/jest-dom'

// jsdom lacks ResizeObserver, which cmdk (command palette) and some Radix
// primitives touch on mount. Provide a no-op so component tests can render.
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// jsdom doesn't implement Element.scrollIntoView (cmdk calls it to keep the
// active item in view). No-op it so the command palette can mount in tests.
if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function scrollIntoView() {}
}

// jsdom lacks the Pointer Capture API + PointerEvent that Radix popper
// primitives (DropdownMenu, Tooltip) probe on open. Polyfill them so the
// overflow-menu can open under fireEvent in component tests.
if (typeof Element !== 'undefined') {
  if (!Element.prototype.hasPointerCapture) {
    Element.prototype.hasPointerCapture = function hasPointerCapture() {
      return false
    }
  }
  if (!Element.prototype.setPointerCapture) {
    Element.prototype.setPointerCapture = function setPointerCapture() {}
  }
  if (!Element.prototype.releasePointerCapture) {
    Element.prototype.releasePointerCapture = function releasePointerCapture() {}
  }
}
if (typeof globalThis.PointerEvent === 'undefined') {
  globalThis.PointerEvent = class PointerEvent extends MouseEvent {
    constructor(type, props = {}) {
      super(type, props)
      this.pointerId = props.pointerId ?? 1
    }
  }
}
