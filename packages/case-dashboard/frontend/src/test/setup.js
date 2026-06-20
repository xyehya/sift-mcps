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
