document.addEventListener('DOMContentLoaded', () => {
  const btnStreamMedia = document.getElementById('btnStreamMedia');
  const btnDownloadFile = document.getElementById('btnDownloadFile');
  const btnUpload = document.getElementById('btnUpload');
  const fileInput = document.getElementById('fileInput');
  const outputLog = document.getElementById('outputLog');

  btnStreamMedia.addEventListener('click', () => {
    fetch('/api/media/stream', {
      headers: { 'Range': 'bytes=0-1023' }
    })
      .then(res => {
        const range = res.headers.get('Content-Range');
        return res.arrayBuffer().then(buf => ({ status: res.status, range, size: buf.byteLength }));
      })
      .then(res => {
        outputLog.innerText = `HTTP ${res.status} Partial Content:\nContent-Range: ${res.range}\nChunk Bytes Received: ${res.size} B`;
      })
      .catch(err => {
        outputLog.innerText = `Stream Error: ${err.message}`;
      });
  });

  btnDownloadFile.addEventListener('click', () => {
    fetch('/api/download')
      .then(res => res.arrayBuffer().then(buf => ({ status: res.status, size: buf.byteLength })))
      .then(res => {
        outputLog.innerText = `HTTP ${res.status} Attachment Download:\nDownloaded Buffer Size: ${res.size} B (${(res.size / 1024).toFixed(2)} KB)`;
      })
      .catch(err => {
        outputLog.innerText = `Download Error: ${err.message}`;
      });
  });

  btnUpload.addEventListener('click', () => {
    const file = fileInput.files[0];
    const payload = file ? file : new Blob(['Test binary payload content for DEMO 03 upload']);

    fetch('/api/upload', {
      method: 'POST',
      body: payload
    })
      .then(res => res.json())
      .then(data => {
        outputLog.innerText = `Upload Success:\n${JSON.stringify(data, null, 2)}`;
      })
      .catch(err => {
        outputLog.innerText = `Upload Error: ${err.message}`;
      });
  });
});
