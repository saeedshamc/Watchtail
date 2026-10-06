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
    var time = shiftTs(event.ts);
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

  /* ---- alerts: toasts + flagged list -------------------------------- */

  function showAlertToast(alert) {
    var host = document.getElementById("alert-toasts");
    if (!host) return;
    var toast = document.createElement("div");
    toast.className = "alert-toast " + (alert.severity || "medium");
    var strong = document.createElement("strong");
    strong.textContent = alert.detector + " · " + (alert.ip || "?");
    var message = document.createElement("div");
    message.className = "small";
    message.textContent = alert.message || "";
    toast.appendChild(strong);
    toast.appendChild(message);
    host.appendChild(toast);
    // Force a reflow so the slide-in animation plays for appended nodes.
    void toast.offsetWidth;
    toast.classList.add("visible");
    setTimeout(function () {
      toast.classList.remove("visible");
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 400);
    }, 8000);
  }

  function setStat(id, value) {
    var el = document.getElementById(id);
    if (el && el.textContent !== String(value)) el.textContent = String(value);
  }

  function markFlaggedRowFresh(ip) {
    var row = document.querySelector('#flagged-list .ip-row[data-ip="' + ip + '"]');
    if (row) {
      row.classList.remove("stale-row");
      return;
    }
    var list = document.getElementById("flagged-list");
    if (!list) return;
    var placeholder = list.querySelector(".muted");
    if (placeholder) placeholder.remove();

    var fresh = document.createElement("div");
    fresh.className = "ip-row fresh-row";
    fresh.dataset.ip = ip;
    var name = document.createElement("span");
    name.className = "ip";
    var link = document.createElement("a");
    link.href = "/ips/" + encodeURIComponent(ip);
    var code = document.createElement("code");
    code.textContent = ip;
    link.appendChild(code);
    name.appendChild(link);
    var badge = document.createElement("span");
    badge.className = "badge flagged";
    badge.textContent = "flagged";
    var reason = document.createElement("span");
    reason.className = "reason";
    reason.textContent = "new alert just received";
    fresh.appendChild(name);
    fresh.appendChild(badge);
    fresh.appendChild(reason);
    list.insertBefore(fresh, list.firstChild);
  }

  function applyStatsSnapshot(payload) {
    var stats = (payload && payload.stats) || {};
    setStat("stat-events", stats.event_count);
    setStat("stat-alerts", stats.alert_count);
    setStat("stat-flagged", stats.flagged_count);
    if (stats.source_count !== undefined) {
      setStat(
        "stat-sources",
        (stats.active_sources || 0) + "/" + (stats.source_count || 0)
      );
    }
  }

  function setSocketState(text, color) {
    var el = document.getElementById("socket-state");
    if (el) {
      el.textContent = text;
      el.style.color = color || "";
    }
  }

  /* ---- review / dismiss without a page reload ----------------------- */

  function wireReviewForms() {
    document.addEventListener("submit", function (ev) {
      var form = ev.target.closest("form.js-review");
      if (!form) return;
      ev.preventDefault();
      var ip = form.dataset.ip;
      var action = (form.querySelector('input[name="action"]') || {}).value;
      var row = form.closest(".ip-row");
      fetch(form.getAttribute("action"), {
        method: "POST",
        headers: { "X-Requested-With": "fetch" },
        body: new URLSearchParams({ action: action || "" }),
      })
        .then(function (response) {
          if (!response.ok) throw new Error("status " + response.status);
          if (row && row.parentNode) row.parentNode.removeChild(row);
          var list = document.getElementById("flagged-list");
          if (list && !list.querySelector(".ip-row") && !list.querySelector(".muted")) {
            var empty = document.createElement("div");
            empty.className = "muted small";
            empty.textContent = "No IPs flagged right now.";
            list.appendChild(empty);
          }
        })
        .catch(function () {
          form.submit(); // fall back to the classic round trip
        });
    });
  }

  /* ---- display timezone (kept in sync with the session) ------------- */

  var tzOffsetMinutes = 0;
  var tzLabel = "UTC";

  function shiftTs(iso) {
    /* ISO UTC timestamp -> "HH:MM:SS" in the viewer's timezone. */
    if (!iso) return "--:--:--";
    var ms = Date.parse(iso.endsWith("Z") ? iso : iso + "Z");
    if (isNaN(ms)) return "--:--:--";
    var shifted = new Date(ms + tzOffsetMinutes * 60000);
    return shifted.toISOString().slice(11, 19);
  }

  function applyTzLabel() {
    var heads = document.querySelectorAll("th[data-tz-label]");
    for (var i = 0; i < heads.length; i++) {
      heads[i].textContent = "time (" + tzLabel + ")";
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
          showAlertToast(alert);
          if (alert.ip) markFlaggedRowFresh(alert.ip);
        });
      }
    });
    socket.on("stats", function (payload) {
      applyStatsSnapshot(payload);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var attrs = document.body.dataset;
    tzOffsetMinutes = parseInt(attrs.tzOffset || "0", 10) || 0;
    if (attrs.tzLabel) tzLabel = attrs.tzLabel;
    applyTzLabel();
    chart = initChart(
      (attrs.chartLabels || "").split(",").filter(Boolean),
      (attrs.chartTraffic || "").split(",").filter(Boolean).map(Number),
      (attrs.chartErrors || "").split(",").filter(Boolean).map(Number)
    );
    wireReviewForms();
    connectSocket();
  });
})();
