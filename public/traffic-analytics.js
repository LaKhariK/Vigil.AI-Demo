const rateCtx = document.getElementById("rateChart");
const riskCtx = document.getElementById("riskChart");
const portCtx = document.getElementById("portChart");

// These small counters feed the dashboard charts from the same live SSE stream
// used by the packet table.
let connectionCount = 0;
let rateData = [];
let labels = [];

let riskCounts = { low:0, med:0, high:0 };
let portCounts = {};

const rateChart = new Chart(rateCtx, {
  type: "line",
  data: {
    labels: labels,
    datasets: [{
      label: "Connections/sec",
      data: rateData,
      borderColor: "#38bdf8",
      tension: 0.3
    }]
  }
});

const riskChart = new Chart(riskCtx, {
  type: "doughnut",
  data: {
    labels: ["Low", "Medium", "High"],
    datasets: [{
      data: [0,0,0],
      backgroundColor: ["#86efac","#fde68a","#fca5a5"]
    }]
  }
});

const portChart = new Chart(portCtx, {
  type: "bar",
  data: {
    labels: [],
    datasets: [{
      label: "Port Frequency",
      data: [],
      backgroundColor: "#2563eb"
    }]
  }
});

// Subscribe to live traffic events streamed from server.js.
const es = new EventSource("/api/live");

es.onmessage = (msg) => {
  const evt = JSON.parse(msg.data);

  connectionCount++;

  // Risk level may already be attached by another page, but defaulting to low
  // keeps the chart stable if the server sends raw rows.
  const risk = evt.risk?.level || "low";
  if(riskCounts[risk] !== undefined) {
    riskCounts[risk]++;
  }

  // Count destination ports so repeated traffic patterns stand out visually.
  if(evt.dport){
    portCounts[evt.dport] = (portCounts[evt.dport] || 0) + 1;
  }
};

// Update graphs every second so the display feels live without redrawing on
// every single packet event.
setInterval(() => {

  labels.push(new Date().toLocaleTimeString());
  rateData.push(connectionCount);

  // Keep the line chart to a short moving window for readability.
  if(labels.length > 20){
    labels.shift();
    rateData.shift();
  }

  connectionCount = 0;

  rateChart.update();

  riskChart.data.datasets[0].data = [
    riskCounts.low,
    riskCounts.med,
    riskCounts.high
  ];
  riskChart.update();

  const sortedPorts = Object.entries(portCounts)
    .sort((a,b)=>b[1]-a[1])
    .slice(0,5);

  portChart.data.labels = sortedPorts.map(p=>p[0]);
  portChart.data.datasets[0].data = sortedPorts.map(p=>p[1]);
  portChart.update();

}, 1000);
