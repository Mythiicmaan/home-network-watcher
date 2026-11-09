/* Home Network Watcher: small progressive enhancements. Everything works without JS. */
(function () {
  "use strict";

  function init(root) {
    root = root || document;

    // MAC addresses are partly hidden; tap to show the full value (tap again to hide).
    root.querySelectorAll("button.mac[data-reveal]").forEach(function (btn) {
      if (btn.dataset.bound) return;
      btn.dataset.bound = "1";
      var masked = btn.textContent;
      btn.addEventListener("click", function () {
        var showing = btn.dataset.shown === "1";
        btn.textContent = showing ? masked : btn.dataset.reveal;
        btn.dataset.shown = showing ? "0" : "1";
      });
    });

    // Destructive buttons ask first.
    root.querySelectorAll("button[data-confirm]").forEach(function (btn) {
      if (btn.dataset.boundConfirm) return;
      btn.dataset.boundConfirm = "1";
      btn.addEventListener("click", function (e) {
        if (!window.confirm(btn.dataset.confirm)) e.preventDefault();
      });
    });

    // Filters that submit as soon as they change.
    root.querySelectorAll("select[data-autosubmit]").forEach(function (sel) {
      if (sel.dataset.bound) return;
      sel.dataset.bound = "1";
      sel.addEventListener("change", function () {
        if (sel.form) sel.form.requestSubmit ? sel.form.requestSubmit() : sel.form.submit();
      });
    });

    // Toasts fade away on their own.
    root.querySelectorAll(".toast").forEach(function (t) {
      setTimeout(function () { t.classList.add("hide"); }, 6000);
    });
  }

  if (window.htmx) {
    window.htmx.onLoad(function (el) { init(el === document.body ? document : el); });
  } else {
    document.addEventListener("DOMContentLoaded", function () { init(document); });
  }
})();
