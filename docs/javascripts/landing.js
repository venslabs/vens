// Scroll-reveal for the landing page. If reduced motion is requested, the
// browser lacks IntersectionObserver, or there is nothing to reveal, this is a
// no-op and the content stays fully visible (the .js-reveal guard is not set).
(function () {
  function init() {
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var els = document.querySelectorAll("[data-reveal]");
    if (reduce || !("IntersectionObserver" in window) || !els.length) return;

    document.documentElement.classList.add("js-reveal");
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });

    els.forEach(function (el) { io.observe(el); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
