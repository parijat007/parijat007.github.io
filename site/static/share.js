// Share row: reveals "Copy link" and, where the browser offers it, the phone's own share menu.
// No network calls, no tracking; links work without this script.
(function () {
  document.querySelectorAll(".share").forEach(function (row) {
    var status = row.querySelector(".share-status");
    var say = function (t) { if (status) { status.textContent = t; setTimeout(function () { status.textContent = ""; }, 2500); } };
    var copy = row.querySelector(".share-copy");
    if (copy && navigator.clipboard) {
      copy.hidden = false;
      copy.addEventListener("click", function () {
        navigator.clipboard.writeText(copy.dataset.url).then(function () { say("Link copied"); }, function () { say("Could not copy"); });
      });
    }
    var native = row.querySelector(".share-native");
    if (native && navigator.share) {
      native.hidden = false;
      native.addEventListener("click", function () {
        navigator.share({ title: native.dataset.title, url: native.dataset.url }).catch(function () {});
      });
    }
  });
})();
