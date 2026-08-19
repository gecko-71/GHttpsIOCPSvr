let currentJwtToken = '';

document.addEventListener('DOMContentLoaded', () => {
  const btnLogin = document.getElementById('btnLogin');
  const btnProfile = document.getElementById('btnProfile');
  const btnAdmin = document.getElementById('btnAdmin');
  const btnWafTest = document.getElementById('btnWafTest');

  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const jwtTextArea = document.getElementById('jwtToken');
  const apiOutput = document.getElementById('apiOutput');

  btnLogin.addEventListener('click', () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();

    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        if (res.status === 200 && res.data.token) {
          currentJwtToken = res.data.token;
          jwtTextArea.value = currentJwtToken;
          apiOutput.innerText = `Login Success!\nUser: ${res.data.user}\nRole: ${res.data.role}`;
        } else {
          apiOutput.innerText = `Login Failed (HTTP ${res.status}):\n${JSON.stringify(res.data, null, 2)}`;
        }
      })
      .catch(err => {
        apiOutput.innerText = `Network Error: ${err.message}`;
      });
  });

  btnProfile.addEventListener('click', () => {
    fetch('/api/protected/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${currentJwtToken}`
      }
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        apiOutput.innerText = `GET /api/protected/profile (HTTP ${res.status}):\n${JSON.stringify(res.data, null, 2)}`;
      })
      .catch(err => {
        apiOutput.innerText = `Error: ${err.message}`;
      });
  });

  btnAdmin.addEventListener('click', () => {
    fetch('/api/protected/admin', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${currentJwtToken}`
      }
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        apiOutput.innerText = `GET /api/protected/admin (HTTP ${res.status}):\n${JSON.stringify(res.data, null, 2)}`;
      })
      .catch(err => {
        apiOutput.innerText = `Error: ${err.message}`;
      });
  });

  btnWafTest.addEventListener('click', () => {
    fetch("/api/status?attack=SELECT+*+FROM+users+WHERE+1%3D1", {
      method: 'GET'
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        apiOutput.innerText = `WAF Inspection Test (HTTP ${res.status}):\n${JSON.stringify(res.data, null, 2)}`;
      })
      .catch(err => {
        apiOutput.innerText = `WAF Block Response: ${err.message}`;
      });
  });
});
