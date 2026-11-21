// Filter the watch table. No network calls, no storage.
document.querySelectorAll(".filters button").forEach((btn) => {
  btn.addEventListener("click", () => {
    const f = btn.dataset.f;
    document.querySelectorAll(".filters button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    document.querySelectorAll("table.watch tbody tr").forEach((tr) => {
      const show = f === "all" || (f === "stack" ? tr.dataset.stack === "yes" : tr.dataset.kind === f);
      tr.hidden = !show;
    });
  });
});
