// Keep relative times true after the page was built: "18 min ago" is recomputed in the reader's browser.
// On the watch page, show "Nothing new since ..." only when the newest item is over three hours old, and
// say plainly if the watch itself has not checked in for over two hours. No network calls, no storage.
(() => {
  const ago = (t) => {
    const m = Math.floor((Date.now() - t) / 60000);
    if (m < 2) return "just now";
    if (m < 60) return `${m} min ago`;
    if (m < 48 * 60) return `${Math.floor(m / 60)} h ago`;
    return `${Math.floor(m / 1440)} days ago`;
  };
  const when = (el) => Date.parse(el.getAttribute("datetime"));
  const tick = () => {
    document.querySelectorAll("time[data-ago]").forEach((el) => {
      const t = when(el);
      if (!Number.isNaN(t)) el.textContent = ago(t);
    });
    const q = document.querySelector("[data-quiet]");
    if (!q) return;
    const latest = Date.parse(q.dataset.latest), checked = Date.parse(q.dataset.checked);
    q.hidden = Date.now() - latest < 3 * 3600e3;
    q.classList.toggle("stale", Date.now() - checked > 2 * 3600e3);
  };
  document.querySelectorAll("time[data-clock]").forEach((el) => {
    const t = when(el);
    if (Number.isNaN(t)) return;
    const d = new Date(t), today = new Date();
    const day = d.toDateString() === today.toDateString() ? "today"
      : d.toDateString() === new Date(today - 864e5).toDateString() ? "yesterday"
      : d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
    el.textContent = `${d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })} ${day}`;
  });
  tick();
  setInterval(tick, 60000);
})();
