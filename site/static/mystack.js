// "My stack": the reader picks categories and vendor words; matching watch rows and brief items are marked.
// Stored only in this browser (localStorage, key wf-stack). Nothing is sent anywhere.
(() => {
  const KEY = "wf-stack";
  const load = () => {
    try {
      const v = JSON.parse(localStorage.getItem(KEY) || "{}");
      return { cats: Array.isArray(v.cats) ? v.cats.map(String) : [], words: Array.isArray(v.words) ? v.words.map(String) : [] };
    } catch (e) { return { cats: [], words: [] }; }
  };
  const save = (v) => { try { localStorage.setItem(KEY, JSON.stringify(v)); return true; } catch (e) { return false; } };
  const words = (s) => s.split(",").map((w) => w.trim().toLowerCase()).filter((w) => w.length > 1).slice(0, 30);

  const mark = () => {
    const v = load();
    const any = v.cats.length || v.words.length;
    document.querySelectorAll("[data-cats]").forEach((el) => {
      const cats = (el.dataset.cats || "").split(" ");
      const text = el.dataset.text || "";
      const mine = !!any && (v.cats.some((c) => cats.includes(c)) || v.words.some((w) => text.includes(w)));
      el.classList.toggle("mine", mine);
      if (el.classList.contains("entry")) {
        let b = el.querySelector(":scope > .mine-badge");
        if (mine && !b) {
          b = document.createElement("span");
          b.className = "mine-badge";
          b.textContent = "Your stack";
          el.appendChild(b);
        } else if (!mine && b) b.remove();
      }
    });
    const btn = document.querySelector("[data-mine-btn]");
    if (btn) btn.disabled = !any;
    document.dispatchEvent(new CustomEvent("mystack"));
  };

  const panel = document.querySelector("[data-mystack]");
  if (panel) {
    const boxes = panel.querySelectorAll("[data-ms-cat]");
    const input = panel.querySelector("[data-ms-words]");
    const status = panel.querySelector(".ms-status");
    const fill = () => {
      const v = load();
      boxes.forEach((b) => { b.checked = v.cats.includes(b.value); });
      input.value = v.words.join(", ");
    };
    fill();
    panel.querySelector("[data-ms-save]").addEventListener("click", () => {
      const ok = save({ cats: [...boxes].filter((b) => b.checked).map((b) => b.value), words: words(input.value) });
      status.textContent = ok ? "Saved in this browser." : "This browser blocks storage, so the choice lasts until you leave the page.";
      mark();
    });
    panel.querySelector("[data-ms-clear]").addEventListener("click", () => {
      try { localStorage.removeItem(KEY); } catch (e) { /* storage blocked */ }
      fill();
      status.textContent = "Cleared.";
      mark();
    });
  }
  mark();
})();
