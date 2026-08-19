document.addEventListener('DOMContentLoaded', () => {
  const btnPing = document.getElementById('btnPing');
  const btnBenchmark = document.getElementById('btnBenchmark');
  const outputLog = document.getElementById('outputLog');

  btnPing.addEventListener('click', () => {
    fetch('/api/http3/ping')
      .then(res => {
        const altSvc = res.headers.get('Alt-Svc');
        return res.json().then(data => ({ status: res.status, altSvc, data }));
      })
      .then(res => {
        outputLog.innerText = `HTTP ${res.status} Ping Response:\nAlt-Svc: ${res.altSvc}\nData: ${JSON.stringify(res.data, null, 2)}`;
      })
      .catch(err => {
        outputLog.innerText = `Ping Error: ${err.message}`;
      });
  });

  btnBenchmark.addEventListener('click', () => {
    fetch('/api/http3/benchmark')
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        outputLog.innerText = `HTTP ${res.status} Benchmark Result:\nData: ${JSON.stringify(res.data, null, 2)}`;
      })
      .catch(err => {
        outputLog.innerText = `Benchmark Error: ${err.message}`;
      });
  });
});
