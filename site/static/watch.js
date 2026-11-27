// Filter the watch table by type and by what is affected. No network calls, no storage.
(() => {
  let type = "all", cat = "";
  const apply = () => document.querySelectorAll("table.watch tbody tr").forEach((tr) => {
    const okType = type === "all" || (type === "stack" ? tr.dataset.stack === "yes" : tr.dataset.kind === type);
    const okCat = !cat || (tr.dataset.cats || "").split(" ").includes(cat);
    tr.hidden = !(okType && okCat);
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
})();
