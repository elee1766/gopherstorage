"use strict";

// Alpine components. The CSP build of Alpine cannot evaluate inline code,
// so behaviour lives here and the markup refers to it by name.
document.addEventListener("alpine:init", () => {
  Alpine.data("copy", () => ({
    label: "",
    init() { this.label = this.$el.textContent.trim(); },
    async copy() {
      const original = this.label;
      try {
        await navigator.clipboard.writeText(this.$el.dataset.copy);
        this.label = "Copied";
      } catch {
        this.label = "Copy failed";
      }
      setTimeout(() => { this.label = original; }, 1500);
    },
  }));

  Alpine.data("toggle", () => ({
    open: false,
    toggle() { this.open = !this.open; },
  }));
});

// Clear the error banner after any successful htmx request.
document.addEventListener("htmx:afterRequest", (e) => {
  if (e.detail.successful) {
    const flash = document.getElementById("flash");
    if (flash) flash.replaceChildren();
  }
});
