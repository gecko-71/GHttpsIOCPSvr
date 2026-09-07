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
    const fileSize = file ? file.size : payload.size;
    const fileName = file ? file.name : 'inline_payload.bin';

    outputLog.innerText = `Starting upload: ${fileName} (${(fileSize / (1024 * 1024)).toFixed(2)} MB)...`;
    btnUpload.disabled = true;

    const startTime = performance.now();
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = ((e.loaded / e.total) * 100).toFixed(1);
        const elapsedSec = (performance.now() - startTime) / 1000;
        const speedMBps = elapsedSec > 0 ? ((e.loaded / (1024 * 1024)) / elapsedSec).toFixed(2) : '0';
        outputLog.innerText = `Uploading file: ${fileName}\n` +
          `Progress: ${percent}%\n` +
          `Transferred: ${(e.loaded / (1024 * 1024)).toFixed(2)} MB / ${(e.total / (1024 * 1024)).toFixed(2)} MB\n` +
          `Transfer Speed: ${speedMBps} MB/s`;
      }
    };

    xhr.onload = () => {
      btnUpload.disabled = false;
      const totalTime = ((performance.now() - startTime) / 1000).toFixed(2);
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const data = JSON.parse(xhr.responseText);
          outputLog.innerText = `Upload completed successfully in ${totalTime}s:\n${JSON.stringify(data, null, 2)}`;
        } catch (_) {
          outputLog.innerText = `Upload completed successfully in ${totalTime}s:\n${xhr.responseText}`;
        }
      } else {
        outputLog.innerText = `Upload error (HTTP ${xhr.status}):\n${xhr.responseText || xhr.statusText}`;
      }
    };

    xhr.onerror = () => {
      btnUpload.disabled = false;
      outputLog.innerText = `Network error / connection aborted during upload.`;
    };

    xhr.ontimeout = () => {
      btnUpload.disabled = false;
      outputLog.innerText = `Upload timed out.`;
    };

    xhr.send(payload);
  });
});
