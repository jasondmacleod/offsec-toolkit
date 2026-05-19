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

  // ===== Phase 2 =====================================================

  // -- result-open beacon: one engagement is enough to clear soft-zero --
  var openSent = false;
  function markOpened() {
    if (openSent) return;
    var ol = document.getElementById("results");
    var qid = ol && ol.getAttribute("data-query-id");
    if (!qid) return;
    openSent = true;
    var body = new URLSearchParams({ query_id: qid });
    if (navigator.sendBeacon) {
      navigator.sendBeacon("/api/result-open", body);
    } else {
      fetch("/api/result-open", { method: "POST", body: body, keepalive: true });
    }
  }

  // -- "didn't help" -> explicit_gap ----------------------------------
  function logDidntHelp(btn) {
    var ol = document.getElementById("results");
    var qid = ol && ol.getAttribute("data-query-id");
    if (!qid || btn.classList.contains("logged")) return;
    var body = new URLSearchParams({
      query_id: qid, chunk_id: btn.getAttribute("data-chunk-id") || ""
    });
    fetch("/api/gap", { method: "POST", body: body }).then(function () {
      btn.classList.add("logged");
      btn.textContent = "✓ logged";
    }).catch(function () { btn.textContent = "err"; });
  }

  // -- pin toggle ------------------------------------------------------
  function togglePin(btn) {
    var body = new URLSearchParams({
      target_type: btn.getAttribute("data-target-type"),
      target_id: btn.getAttribute("data-target-id")
    });
    fetch("/api/pin", { method: "POST", body: body })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var on = !!d.pinned;
        btn.classList.toggle("pinned", on);
        btn.setAttribute("aria-pressed", on ? "true" : "false");
        var ico = btn.querySelector(".pin-ico");
        var lab = btn.querySelector(".pin-label");
        if (ico) ico.textContent = on ? "★" : "☆";
        if (lab) lab.textContent = on ? "pinned" : "pin";
      }).catch(function () {});
  }

  // -- related sidebar toggle -----------------------------------------
  function toggleRelated() {
    var aside = document.getElementById("related-aside");
    if (!aside) return;
    aside.classList.toggle("collapsed");
    aside.classList.toggle("force-open");
  }

  document.addEventListener("click", function (e) {
    var btn;
    if ((btn = e.target.closest(".didnt-help"))) { logDidntHelp(btn); return; }
    if ((btn = e.target.closest("#pin-btn"))) { togglePin(btn); return; }
    if (e.target.closest("#related-toggle")) { toggleRelated(); return; }
    if (e.target.closest(".copy-btn")) { markOpened(); return; }
    // Engaging with a result (open link or expand the card) clears soft-zero.
    if (e.target.closest("#results .result a") ||
        e.target.closest("#results .result")) { markOpened(); }
  });

  document.addEventListener("keydown", function (e) {
    if (isTyping(e)) return;
    if (e.key === "p") {
      var pb = document.getElementById("pin-btn");
      if (pb) { e.preventDefault(); togglePin(pb); }
      return;
    }
    if (e.key === "r") {
      if (document.getElementById("related-aside")) {
        e.preventDefault(); toggleRelated();
      }
      return;
    }
    if (e.key === "Enter" && selected()) { markOpened(); }
  });

  // -- /pins drag reorder (no library; HTML5 DnD) ---------------------
  (function () {
    var list = document.getElementById("pin-reorder");
    if (!list) return;
    var dragEl = null;
    list.querySelectorAll("li").forEach(function (li) {
      var h = li.querySelector(".drag-handle");
      if (!h) return;
      h.setAttribute("draggable", "true");
      h.addEventListener("dragstart", function (ev) {
        dragEl = li; li.classList.add("dragging");
        ev.dataTransfer.effectAllowed = "move";
      });
      h.addEventListener("dragend", function () {
        li.classList.remove("dragging");
        if (!dragEl) return;
        dragEl = null;
        var ids = Array.prototype.map.call(
          list.querySelectorAll("li"), function (x) { return x.getAttribute("data-pin-id"); });
        var body = new URLSearchParams();
        ids.forEach(function (id) { body.append("pin_id", id); });
        fetch("/api/pins/reorder", { method: "POST", body: body });
      });
    });
    list.addEventListener("dragover", function (ev) {
      ev.preventDefault();
      if (!dragEl) return;
      var after = null;
      list.querySelectorAll("li:not(.dragging)").forEach(function (li) {
        var box = li.getBoundingClientRect();
        if (ev.clientY > box.top + box.height / 2) after = li;
      });
      if (after && after.nextSibling !== dragEl) {
        list.insertBefore(dragEl, after.nextSibling);
      } else if (!after && list.firstElementChild !== dragEl) {
        list.insertBefore(dragEl, list.firstElementChild);
      }
    });
  })();
})();
