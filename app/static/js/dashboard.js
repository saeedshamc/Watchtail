/* Dashboard behaviour: traffic/4xx chart plus Socket.IO live updates. */
(function () {
  "use strict";

  var MAX_ROWS = 40;
  var chart = null;

  function initChart(labels, traffic, errors) {
    var canvas = document.getElementById("traffic-chart");
    if (!canvas || typeof Chart === "undefined") return null;
    return new Chart(canvas, {
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
  }

  function rollChartMinute(minuteLabel) {
    chart.data.labels.push(minuteLabel);
    chart.data.labels.shift();
    chart.data.datasets.forEach(function (dataset) {
      dataset.data.push(0);
      dataset.data.shift();
    });
  }

  function bumpChart(tsIso, is4xx) {
    if (!chart) return;
    var minute = (tsIso || "").slice(11, 16);
    var labels = chart.data.labels;
    var last = labels[labels.length - 1];
    if (minute && minute !== last) rollChartMinute(minute);
    var traffic = chart.data.datasets[0].data;
    traffic[traffic.length - 1] += 1;
    if (is4xx) {
      var errors = chart.data.datasets[1].data;
      errors[errors.length - 1] += 1;
    }
    chart.update();
  }

  function addEventRow(event) {
    var tbody = document.getElementById("event-rows");
    if (!tbody) return;
    var placeholder = tbody.querySelector("td.muted");
    if (placeholder) tbody.innerHTML = "";

    var tr = document.createElement("tr");
    var time = (event.ts || "").slice(11, 19) || "--:--:--";
    var request = event.method
      ? event.method + " " + (event.path || "")
      : event.kind;
    var kindBadge = event.kind === "ssh_auth_fail" ? "high" : "ok";

    var tdTime = document.createElement("td");
    tdTime.textContent = time;
    var tdKind = document.createElement("td");
    var badge = document.createElement("span");
    badge.className = "badge " + kindBadge;
    badge.textContent = event.kind;
    tdKind.appendChild(badge);
    var tdIp = document.createElement("td");
    var code = document.createElement("code");
    code.textContent = event.ip || "-";
    tdIp.appendChild(code);
    var tdRequest = document.createElement("td");
    tdRequest.className = "small";
    tdRequest.textContent = request;
    var tdStatus = document.createElement("td");
    tdStatus.className = "num";
    tdStatus.textContent = event.status || "";

    tr.appendChild(tdTime);
    tr.appendChild(tdKind);
    tr.appendChild(tdIp);
    tr.appendChild(tdRequest);
    tr.appendChild(tdStatus);
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
  }

  function setSocketState(text, color) {
    var el = document.getElementById("socket-state");
    if (el) {
      el.textContent = text;
      el.style.color = color || "";
    }
  }

  function connectSocket() {
    if (typeof io === "undefined") {
      setSocketState("live updates unavailable");
      return;
    }
    var socket = io();
    socket.on("connect", function () {
      setSocketState("live", "#57b576");
    });
    socket.on("disconnect", function () {
      setSocketState("reconnecting…", "#8a94a3");
    });
    socket.on("activity", function (payload) {
      if (!payload) return;
      if (payload.event) {
        addEventRow(payload.event);
        bumpChart(payload.event.ts, payload.event.status >= 400);
      }
      if (payload.alerts && payload.alerts.length) {
        payload.alerts.forEach(function (alert) {
          console.info("watchtail alert:", alert.detector, alert.ip, alert.message);
        });
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var attrs = document.body.dataset;
    chart = initChart(
      (attrs.chartLabels || "").split(",").filter(Boolean),
      (attrs.chartTraffic || "").split(",").filter(Boolean).map(Number),
      (attrs.chartErrors || "").split(",").filter(Boolean).map(Number)
    );
    connectSocket();
  });
})();
