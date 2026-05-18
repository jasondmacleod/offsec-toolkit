/* vquery — keyboard-first, no framework.
   /  focus search   ↑↓ move   Enter expand   Esc clear/collapse
   o  toggle source path (chunk/doc views)
*/
(function () {
  "use strict";

  function isTyping(e) {
    var t = (e.target.tagName || "").toLowerCase();
    return t === "input" || t === "textarea" || e.target.isContentEditable;
  }
  function results() {
    return Array.prototype.slice.call(document.querySelectorAll(".result"));
  }
  function selected() { return document.querySelector(".result.selected"); }

  function select(idx) {
    var r = results();
    if (!r.length) return;
    idx = Math.max(0, Math.min(r.length - 1, idx));
    r.forEach(function (el) { el.classList.remove("selected"); });
    r[idx].classList.add("selected");
    r[idx].scrollIntoView({ block: "nearest" });
    r[idx].focus({ preventScroll: true });
  }

  function addCopyButtons(root) {
    (root || document).querySelectorAll(".md-body pre").forEach(function (pre) {
      if (pre.querySelector(".copy-btn")) return;
      var b = document.createElement("button");
      b.type = "button"; b.className = "copy-btn"; b.textContent = "copy";
      pre.appendChild(b);
    });
  }

  function toggleExpand(li) {
    var box = li.querySelector(".expansion");
    if (!box) return;
    if (!box.hidden) { box.hidden = true; box.innerHTML = ""; return; }
    var url = li.getAttribute("data-expand");
    if (!url) return;
    box.innerHTML = '<p class="muted">loading…</p>';
    box.hidden = false;
    fetch(url, { headers: { "X-Requested-With": "fetch" } })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        box.innerHTML = html;
        addCopyButtons(box);
      })
      .catch(function () { box.innerHTML = '<p class="muted">failed to load</p>'; });
  }

  function collapseAll() {
    var any = false;
    document.querySelectorAll(".expansion").forEach(function (b) {
      if (!b.hidden) { b.hidden = true; b.innerHTML = ""; any = true; }
    });
    return any;
  }

  document.addEventListener("keydown", function (e) {
    var q = document.getElementById("q");

    if (e.key === "/" && !isTyping(e)) {
      e.preventDefault();
      if (q) { q.focus(); q.select(); }
      return;
    }

    if (e.key === "o" && !isTyping(e)) {
      var sl = document.querySelectorAll(".source-line");
      if (sl.length) {
        e.preventDefault();
        sl.forEach(function (el) { el.hidden = !el.hidden; });
      }
      return;
    }

    if (e.key === "Escape") {
      if (collapseAll()) return;
      if (q) { q.value = ""; q.focus(); }
      return;
    }

    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      var r = results();
      if (!r.length) return;
      // From the search box, ArrowDown drops into the result list.
      if (document.activeElement === q) {
        if (e.key === "ArrowDown") { e.preventDefault(); q.blur(); select(0); }
        return;
      }
      var cur = selected();
      var idx = cur ? r.indexOf(cur) : -1;
      e.preventDefault();
      select(idx + (e.key === "ArrowDown" ? 1 : -1));
      return;
    }

    if (e.key === "Enter" && document.activeElement !== q) {
      var cur2 = selected();
      if (cur2) { e.preventDefault(); toggleExpand(cur2); }
    }
  });

  // Click a card (not its links) to expand; links navigate normally.
  document.addEventListener("click", function (e) {
    var copy = e.target.closest(".copy-btn");
    if (copy) {
      var pre = copy.closest("pre");
      var code = pre ? pre.querySelector("code") || pre : null;
      var txt = code ? (code.innerText || code.textContent) : "";
      navigator.clipboard.writeText(txt).then(function () {
        copy.textContent = "copied"; copy.classList.add("copied");
        setTimeout(function () {
          copy.textContent = "copy"; copy.classList.remove("copied");
        }, 1200);
      }).catch(function () { copy.textContent = "err"; });
      return;
    }
    if (e.target.closest("a")) return;
    var li = e.target.closest(".result");
    if (li) {
      results().forEach(function (el) { el.classList.remove("selected"); });
      li.classList.add("selected");
      toggleExpand(li);
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    addCopyButtons(document);
  });
})();
