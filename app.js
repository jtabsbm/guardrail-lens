const toast = document.querySelector("[data-toast]");
let toastTimer;

const copy = {
  pitch:
    "Quick question: are inference cost, latency, or agent reliability becoming a bottleneck? I run a five-day, fixed-scope teardown that instruments the real path, identifies the highest-leverage changes, and leaves a benchmark your team can rerun. Worth a 15-minute fit check?",
  email:
    "Subject: A five-day teardown for your AI serving bottleneck\n\nHi [Name],\n\nI noticed [specific product/model/use case]. If inference cost, latency, or agent reliability is becoming a constraint, I can run a five-business-day teardown: baseline the real path, isolate the bottleneck, implement one focused improvement, and leave you with before/after evidence.\n\nThe fixed sprint is $7,500. If useful, I can start with a $1,500 diagnostic credited toward the sprint.\n\nOpen to a 15-minute fit check this week?\n\nBest,\nJames",
  intake:
    "1. What model/runtime is in production?\n2. What is the current cost per task or 1M tokens?\n3. What latency or throughput target matters?\n4. Where do failures show up: model, retrieval, tools, routing, or infra?\n5. What telemetry or traces can we access?\n6. What would make this sprint an obvious win?",
};

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("is-visible"), 3600);
}

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = copy[button.dataset.copy];
    try {
      await navigator.clipboard.writeText(value);
      showToast("Copied. Personalize the bracketed fields before sending.");
    } catch {
      showToast(value);
    }
  });
});
