// "Copy as ticket": shows the copy button only where the clipboard is available; the text stays selectable anyway.
(() => {
  if (!navigator.clipboard) return;
  document.querySelectorAll("details.ticket").forEach((d) => {
    const btn = d.querySelector("[data-copy]");
    const pre = d.querySelector("pre");
    const out = d.querySelector(".copied");
    if (!btn || !pre) return;
    btn.hidden = false;
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(pre.textContent).then(
        () => { out.textContent = "Copied."; },
        () => { out.textContent = "Copy blocked by the browser; select the text instead."; });
    });
  });
})();
