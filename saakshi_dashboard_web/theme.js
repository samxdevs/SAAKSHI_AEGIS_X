/* Light/dark switch. Loaded in <head> so the saved choice applies before the page paints (no flash).
   With no saved choice the page follows the device setting. */
(function () {
  "use strict";
  var KEY = "saakshi-theme", root = document.documentElement;
  function saved() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  var s = saved();
  if (s === "light" || s === "dark") root.setAttribute("data-theme", s);

  var ICON = {   // static markup only
    dark: '<path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11Z" fill="currentColor"/>',
    light: '<circle cx="12" cy="12" r="4.5" fill="currentColor"/><g stroke="currentColor" stroke-width="2" stroke-linecap="round">' +
      '<path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"/></g>'
  };
  function paint(btn) {
    var next = current() === "dark" ? "light" : "dark";
    btn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICON[next] + "</svg>";
    btn.setAttribute("aria-label", "Switch to " + next + " mode");
    btn.title = "Switch to " + next + " mode";
  }
  function toggle() {
    var next = current() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem(KEY, next); } catch (e) { /* private mode: still switches for this visit */ }
    document.querySelectorAll(".theme-toggle").forEach(paint);
  }
  window.saakshiThemeButton = function () {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "btn small theme-toggle";
    b.addEventListener("click", toggle);
    paint(b);
    return b;
  };
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-theme-slot]").forEach(function (slot) { slot.replaceWith(window.saakshiThemeButton()); });
  });
  if (window.matchMedia) {
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
      document.querySelectorAll(".theme-toggle").forEach(paint);
    });
  }
})();
