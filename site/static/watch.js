// Filter the watch table by type, priority, what is affected and the reader's stack. No network calls.
(() => {
  let type = "all", cat = "", prio = "";
  const apply = () => document.querySelectorAll("table.watch tbody tr").forEach((tr) => {
    const okType = type === "all" || (type === "stack" ? tr.dataset.stack === "yes"
      : type === "mine" ? tr.classList.contains("mine") : tr.dataset.kind === type);
    const okCat = !cat || (tr.dataset.cats || "").split(" ").includes(cat);
    const okPrio = !prio || tr.dataset.prio === prio;
    tr.hidden = !(okType && okCat && okPrio);
  });
  document.querySelectorAll(".filters button").forEach((btn) => {
    btn.addEventListener("click", () => {
      type = btn.dataset.f;
      document.querySelectorAll(".filters button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
      apply();
    });
  });
  const sel = document.querySelector(".filters select[data-cat]");
  if (sel) sel.addEventListener("change", () => { cat = sel.value; apply(); });
  const ps = document.querySelector(".filters select[data-prio]");
  if (ps) ps.addEventListener("change", () => { prio = ps.value; apply(); });
  document.addEventListener("mystack", apply);
})();
