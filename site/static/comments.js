// Comments load only when the reader asks: until then no request goes to GitHub or giscus.
document.querySelectorAll("button[data-comments]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const s = document.createElement("script");
    s.src = "https://giscus.app/client.js";
    s.async = true;
    s.crossOrigin = "anonymous";
    const set = { repo: btn.dataset.repo, "repo-id": btn.dataset.repoId, category: btn.dataset.category,
      "category-id": btn.dataset.categoryId, mapping: "specific", term: btn.dataset.term, strict: "1",
      "reactions-enabled": "1", "emit-metadata": "0", "input-position": "top", theme: "dark_dimmed",
      lang: "en", loading: "lazy" };
    Object.entries(set).forEach(([k, v]) => s.setAttribute(`data-${k}`, v));
    btn.after(s);
    btn.remove();
  }, { once: true });
});
