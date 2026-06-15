document.addEventListener('DOMContentLoaded', () => {
  // Init
  loadDevices();
  loadLogs();
  setupSSE();

  // Dialog Controls
  const authDialog = document.getElementById('auth-dialog');
  const macInput = document.getElementById('auth-mac');
  const aliasInput = document.getElementById('auth-alias');
  const closeBtn = document.getElementById('dialog-close');
  const form = document.getElementById('auth-form');

  window.openAuthDialog = (mac) => {
    macInput.value = mac;
    aliasInput.value = '';
    authDialog.classList.add('active');
    aliasInput.focus();
  };

  closeBtn.addEventListener('click', () => {
    authDialog.classList.remove('active');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const mac = macInput.value;
    const alias = aliasInput.value;

    try {
      const response = await fetch('/api/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac, alias })
      });

      if (response.ok) {
        authDialog.classList.remove('active');
        loadDevices();
        addLogEntry('join', `Authorized device: ${mac} as "${alias}"`);
      } else {
        alert('Failed to authorize device');
      }
    } catch (err) {
      console.error(err);
    }
  });

  window.deauthorizeDevice = async (mac) => {
    if (!confirm(`Are you sure you want to deauthorize device ${mac}?`)) return;

    try {
      const response = await fetch('/api/deauthorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac })
      });

      if (response.ok) {
        loadDevices();
        addLogEntry('leave', `Deauthorized device: ${mac}`);
      } else {
        alert('Failed to deauthorize device');
      }
    } catch (err) {
      console.error(err);
    }
  };
});

// Load Active & Saved Devices
async function loadDevices() {
  try {
    const response = await fetch('/api/devices');
    const devices = await response.json();
    renderDevicesTable(devices || []);
    updateStats(devices || []);
  } catch (err) {
    console.error('Error fetching devices:', err);
  }
}

// Load Event Logs
async function loadLogs() {
  try {
    const response = await fetch('/api/events?limit=20');
    const logs = await response.json();
    const logContainer = document.getElementById('logs');
    logContainer.innerHTML = '';

    if (logs && logs.length > 0) {
      logs.forEach(log => {
        let type = log.event_type;
        if (type === 'join') type = 'join';
        else if (type === 'leave') type = 'leave';
        
        const time = new Date(log.timestamp).toLocaleTimeString();
        const msg = `${log.hostname} (${log.ip}) ${log.event_type === 'join' ? 'connected' : 'disconnected'}`;
        addLogEntry(type, msg, time);
      });
    } else {
      logContainer.innerHTML = '<div class="log-entry">No events logged yet.</div>';
    }
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

// Render Devices list to the table
function renderDevicesTable(devices) {
  const tbody = document.getElementById('device-list');
  tbody.innerHTML = '';

  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Scanning network... No active devices found yet.</td></tr>';
    return;
  }

  devices.forEach(d => {
    const tr = document.createElement('tr');
    
    // Status Badge
    let statusBadge = '';
    let actionBtn = '';
    
    if (d.is_gateway) {
      statusBadge = '<span class="status-badge status-gateway">Gateway</span>';
      actionBtn = '<span style="color: var(--text-muted); font-size: 0.8rem;">System</span>';
    } else if (d.authorized) {
      const displayName = d.alias || 'Known Host';
      statusBadge = `<span class="status-badge status-auth" title="${d.mac}">Authorized (${displayName})</span>`;
      actionBtn = `<button class="btn btn-secondary" onclick="deauthorizeDevice('${d.mac}')">Deauthorize</button>`;
    } else {
      statusBadge = '<span class="status-badge status-unauth">Unauthorized / Unknown</span>';
      actionBtn = `<button class="btn" onclick="openAuthDialog('${d.mac}')">Authorize</button>`;
    }

    // Ports
    const portsHtml = d.open_ports && d.open_ports.length > 0 
      ? d.open_ports.map(p => `<span class="port-tag">${p}</span>`).join('')
      : '<span style="color: var(--text-muted); font-size: 0.8rem;">None detected</span>';

    tr.innerHTML = `
      <td style="font-weight: 600;">${d.ip}</td>
      <td>${d.hostname || 'Unknown'}</td>
      <td style="font-family: monospace;">${d.mac}</td>
      <td>${statusBadge}</td>
      <td>${portsHtml}</td>
      <td>${actionBtn}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Update Stats Panels
function updateStats(devices) {
  const totalCount = devices.length;
  const authCount = devices.filter(d => d.authorized && !d.is_gateway).length;
  const gatewayCount = devices.filter(d => d.is_gateway).length;
  const intruderCount = devices.filter(d => !d.authorized && !d.is_gateway).length;

  document.getElementById('stat-total').innerText = totalCount;
  document.getElementById('stat-authorized').innerText = authCount;
  document.getElementById('stat-gateways').innerText = gatewayCount;
  
  const intruderEl = document.getElementById('stat-intruders');
  intruderEl.innerText = intruderCount;
  if (intruderCount > 0) {
    intruderEl.style.color = 'var(--status-unauth)';
  } else {
    intruderEl.style.color = 'var(--status-auth)';
  }
}

// Setup Server-Sent Events (SSE)
function setupSSE() {
  const eventSource = new EventSource('/events');

  eventSource.onopen = () => {
    console.log('SSE Stream established successfully.');
    document.getElementById('status-indicator').innerText = 'Connected Live';
    document.getElementById('status-indicator').style.color = 'var(--status-auth)';
  };

  eventSource.onerror = (err) => {
    console.error('SSE connection error:', err);
    document.getElementById('status-indicator').innerText = 'Reconnecting...';
    document.getElementById('status-indicator').style.color = 'var(--status-unauth)';
  };

  eventSource.onmessage = (event) => {
    try {
      const evt = JSON.parse(event.data);
      console.log('Received SSE Event:', evt);

      const time = new Date(evt.timestamp).toLocaleTimeString();

      switch (evt.type) {
        case 'scan_complete':
          loadDevices();
          document.getElementById('last-scan-time').innerText = time;
          addLogEntry('info', evt.data, time);
          break;

        case 'join':
          loadDevices();
          addLogEntry('join', `Device joined: ${evt.data.hostname || 'Unknown'} (${evt.data.ip})`, time);
          break;

        case 'leave':
          loadDevices();
          addLogEntry('leave', `Device disconnected: ${evt.data.hostname || 'Unknown'} (${evt.data.ip})`, time);
          break;

        case 'ip_change':
          loadDevices();
          addLogEntry('info', `Device IP change: ${evt.data.mac} shifted to ${evt.data.ip}`, time);
          break;

        case 'alert':
          loadDevices();
          addLogEntry('alert', `⚠️ SECURITY ALERT: Unauthorized device connected! IP: ${evt.data.ip} (${evt.data.hostname})`, time);
          if (Notification.permission === 'granted') {
            new Notification('🚨 LAN Sentinel Intruder Alert!', {
              body: `Unknown device joined: ${evt.data.ip} (${evt.data.mac})`
            });
          }
          break;
      }
    } catch (e) {
      console.error('Error parsing SSE event data:', e);
    }
  };

  if (Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

// Helper to add logs dynamically
function addLogEntry(type, msg, timeStr) {
  const logContainer = document.getElementById('logs');
  const time = timeStr || new Date().toLocaleTimeString();
  
  const div = document.createElement('div');
  div.className = `log-entry ${type}`;
  div.innerHTML = `<span class="log-time">[${time}]</span> ${msg}`;
  
  if (logContainer.innerText === 'No events logged yet.') {
    logContainer.innerHTML = '';
  }
  
  logContainer.insertBefore(div, logContainer.firstChild);

  if (logContainer.children.length > 50) {
    logContainer.removeChild(logContainer.lastChild);
  }
}
