/* Dashboard behaviour: traffic/4xx chart rendering. */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    var canvas = document.getElementById("traffic-chart");
    if (!canvas || typeof Chart === "undefined") return;

    var attrs = document.body.dataset;
    var labels = (attrs.chartLabels || "").split(",").filter(Boolean);
    var traffic = (attrs.chartTraffic || "").split(",").filter(Boolean).map(Number);
    var errors = (attrs.chartErrors || "").split(",").filter(Boolean).map(Number);

    new Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "requests/min",
            data: traffic,
            borderColor: "#4fa3e3",
            backgroundColor: "rgba(79,163,227,0.15)",
            tension: 0.3,
            fill: true,
          },
          {
            label: "4xx/min",
            data: errors,
            borderColor: "#e35d5d",
            backgroundColor: "rgba(227,93,93,0.10)",
            tension: 0.3,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        animation: false,
        scales: {
          x: { ticks: { color: "#8a94a3" }, grid: { color: "rgba(42,50,61,0.6)" } },
          y: {
            beginAtZero: true,
            ticks: { color: "#8a94a3", precision: 0 },
            grid: { color: "rgba(42,50,61,0.6)" },
          },
        },
        plugins: { legend: { labels: { color: "#d8dee6" } } },
      },
    });
  });
})();
