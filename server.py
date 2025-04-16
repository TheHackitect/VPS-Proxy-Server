#!/usr/bin/env python3
"""
VPN/Proxy Server with:
  - Admin Time Zone Setting
  - Detailed Server Stats in Header
  - Usage Limit in MB
  - Badges for Connection & Ban State
  - Side-by-side Charts (Line & Pie), No Animation
  - Table Update Pause While Dropdown is Open
"""

import os
import threading
import socket
import sys
import time
import configparser
import json
import requests
from datetime import datetime
from io import StringIO
import csv

from flask import (
    Flask, render_template_string, request, redirect,
    url_for, session, jsonify, make_response
)
from werkzeug.serving import make_server

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Boolean, BigInteger
)
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session

import logging

# ------------- Time Zones (pytz) -------------
try:
    import pytz
    TIMEZONES_LIST = pytz.all_timezones  # full list
except ImportError:
    # If pytz is not installed, you can ask the admin to install or fallback
    TIMEZONES_LIST = ["UTC", "America/New_York", "Europe/London", "Asia/Shanghai"]

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------
CONFIG_FILE = "server_config.ini"
config = configparser.ConfigParser()

default_config = {
    'SERVER': {
        'proxy_tcp_port': '12345',
        'http_port': '8080',
        'db_uri': 'sqlite:///vpnserver.db',
        'time_zone': 'UTC'
    },
    'AUTH': {
        'username': 'admin',
        'password': 'password'
    }
}

if not os.path.exists(CONFIG_FILE):
    config.read_dict(default_config)
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
else:
    config.read(CONFIG_FILE)

PROXY_TCP_PORT = int(config['SERVER'].get('proxy_tcp_port', '12345'))
HTTP_PORT      = int(config['SERVER'].get('http_port', '8080'))
DB_URI         = config['SERVER'].get('db_uri', 'sqlite:///vpnserver.db')
ADMIN_TZ       = config['SERVER'].get('time_zone', 'UTC')  # e.g. "America/New_York"
VPN_USERNAME   = config['AUTH'].get('username', 'admin')
VPN_PASSWORD   = config['AUTH'].get('password', 'password')

# Helper: Convert a UTC datetime to the admin’s configured time zone
def to_admin_tz(dt_utc):
    if not dt_utc:
        return ""
    try:
        # If pytz is installed:
        if 'pytz' in sys.modules:
            local_tz = pytz.timezone(ADMIN_TZ)
            return dt_utc.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")
        else:
            # fallback: just display UTC
            return dt_utc.strftime("%Y-%m-%d %H:%M:%S") + " (UTC)"
    except:
        return dt_utc.strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------------------------------------------
# Server Location Info (Best-effort)
# -----------------------------------------------------------------
# We attempt to discover the server's public IP & location at startup for display.
SERVER_PUBLIC_IP = "127.0.0.1"
SERVER_COUNTRY   = "Unknown"

def get_server_details():
    global SERVER_PUBLIC_IP, SERVER_COUNTRY
    try:
        # 1) discover public IP
        #   The call below might fail if there's no external access.
        ip_resp = requests.get("https://api.ipify.org", timeout=5)
        if ip_resp.status_code == 200:
            SERVER_PUBLIC_IP = ip_resp.text.strip()
        # 2) geolocate
        loc_resp = requests.get(f"http://ip-api.com/json/{SERVER_PUBLIC_IP}", timeout=5)
        if loc_resp.status_code == 200:
            data = loc_resp.json()
            SERVER_COUNTRY = data.get("country", "Unknown")
    except:
        pass

# Attempt to run once on load:
try:
    get_server_details()
except:
    pass

# -----------------------------------------------------------------
# Database
# -----------------------------------------------------------------
Base = declarative_base()

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    ip = Column(String, nullable=False, unique=True)
    port = Column(Integer, nullable=True)

    connection_start = Column(DateTime)
    last_seen = Column(DateTime)
    total_sent = Column(BigInteger, default=0)
    total_received = Column(BigInteger, default=0)

    data_limit = Column(BigInteger, default=0)  # bytes
    location = Column(String, default="")
    active = Column(Boolean, default=True)
    banned = Column(Boolean, default=False)

class ConnectionLog(Base):
    __tablename__ = "connection_logs"
    id = Column(Integer, primary_key=True)
    client_ip = Column(String)
    timestamp = Column(DateTime)
    sent = Column(BigInteger, default=0)
    received = Column(BigInteger, default=0)

engine = create_engine(DB_URI, echo=False, future=True)
Base.metadata.create_all(engine)
SessionFactory = sessionmaker(bind=engine)
DBSession = scoped_session(SessionFactory)

# -----------------------------------------------------------------
# Logging
# -----------------------------------------------------------------
LOG_FILE = "server.log"
MAX_LOG_LINES = 1000

logger = logging.getLogger("VPNLogger")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def truncate_logfile():
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()
    if len(lines) > MAX_LOG_LINES:
        lines = lines[-MAX_LOG_LINES:]
        with open(LOG_FILE, 'w') as f:
            f.writelines(lines)

def log_message(level, msg):
    if level == 'info':
        logger.info(msg)
    elif level == 'warning':
        logger.warning(msg)
    elif level == 'error':
        logger.error(msg)
    else:
        logger.debug(msg)
    truncate_logfile()

# -----------------------------------------------------------------
# Proxy Service Globals
# -----------------------------------------------------------------
proxy_server_socket = None
proxy_thread = None
proxy_stop_event = threading.Event()
proxy_server_lock = threading.Lock()

# Key = IP, Value = list of open sockets
active_connections = {}

# -----------------------------------------------------------------
# Utility: usage in MB or GB
# -----------------------------------------------------------------
def bytes_to_mb_or_gb(b: int) -> str:
    """Always display as MB or GB only."""
    gig = 1024**3
    if b >= gig:
        return f"{b / gig:.2f} GB"
    else:
        meg = 1024**2
        return f"{b / meg:.2f} MB"

# -----------------------------------------------------------------
# Geolocation for Clients
# -----------------------------------------------------------------
def get_location(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("country", "Unknown")
    except:
        pass
    return "Unknown"

# -----------------------------------------------------------------
# Proxy Controls
# -----------------------------------------------------------------
def start_proxy():
    global proxy_server_socket, proxy_thread
    with proxy_server_lock:
        if proxy_thread and proxy_thread.is_alive():
            return False, "Proxy is already running."
        proxy_stop_event.clear()

        if proxy_server_socket:
            try:
                proxy_server_socket.close()
            except:
                pass

        try:
            proxy_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_server_socket.bind(('0.0.0.0', PROXY_TCP_PORT))
            proxy_server_socket.listen(100)
        except Exception as e:
            err_msg = f"Failed to bind on port {PROXY_TCP_PORT}: {e}"
            log_message('error', err_msg)
            return False, err_msg

        def server_loop():
            log_message('info', f"Proxy started on port {PROXY_TCP_PORT}")
            proxy_server_socket.settimeout(1)
            while not proxy_stop_event.is_set():
                try:
                    client_sock, addr = proxy_server_socket.accept()
                    threading.Thread(
                        target=handle_proxy_client,
                        args=(client_sock, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as ex:
                    log_message('error', f"Accept error: {ex}")
                    break
            try:
                proxy_server_socket.close()
            except:
                pass
            log_message('info', "Proxy server stopped.")

        proxy_thread = threading.Thread(target=server_loop, daemon=True)
        proxy_thread.start()
        return True, "Proxy started."

def stop_proxy():
    global proxy_server_socket, proxy_thread
    with proxy_server_lock:
        if not proxy_thread or not proxy_thread.is_alive():
            return False, "Proxy not running."
        proxy_stop_event.set()
        proxy_thread.join(timeout=5)
        proxy_thread = None
        return True, "Proxy stopped."

def restart_proxy():
    stop_proxy()
    time.sleep(1)
    started, msg = start_proxy()
    return started, msg

def get_proxy_status():
    with proxy_server_lock:
        return (proxy_thread is not None) and proxy_thread.is_alive()

# -----------------------------------------------------------------
# Tunneling logic
# -----------------------------------------------------------------
import math
import datetime

def tunnel(src, dst, client_ip, direction):
    """
    Forwards data & updates usage in DB. direction: "src->dst" or "dst->src"
    """
    while True:
        try:
            data = src.recv(4096)
            if not data:
                break
            amount = len(data)

            session_db = DBSession()
            try:
                c = session_db.query(Client).filter(Client.ip == client_ip).first()
                if not c:
                    break

                if direction == "src->dst":
                    c.total_sent += amount
                else:
                    c.total_received += amount

                c.last_seen = datetime.datetime.utcnow()

                # log chunk
                cl = ConnectionLog(
                    client_ip=client_ip,
                    timestamp=datetime.datetime.utcnow(),
                    sent=amount if direction == "src->dst" else 0,
                    received=amount if direction == "dst->src" else 0
                )
                session_db.add(cl)

                # check limit
                if c.data_limit > 0:
                    used = c.total_sent + c.total_received
                    if used >= c.data_limit:
                        log_message('info', f"{client_ip} exceeded limit. Closing.")
                        session_db.commit()
                        break

                session_db.commit()
            except Exception as ex:
                session_db.rollback()
                log_message('error', f"DB usage update error: {ex}")
            finally:
                session_db.close()

            dst.sendall(data)
        except:
            break

def handle_proxy_client(client_socket, addr):
    ip, port = addr[0], addr[1]
    log_message('info', f"New connection from {ip}:{port}")

    session_db = DBSession()
    try:
        c = session_db.query(Client).filter(Client.ip == ip).first()
        if not c:
            c = Client(
                ip=ip,
                port=port,
                connection_start=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
                total_sent=0,
                total_received=0,
                data_limit=0,
                location=get_location(ip),
                active=True,
                banned=False
            )
            session_db.add(c)
            session_db.commit()
        else:
            # check ban
            if c.banned:
                log_message('info', f"{ip} is banned. Rejecting.")
                client_socket.close()
                session_db.close()
                return
            # check limit
            used = c.total_sent + c.total_received
            if c.data_limit > 0 and used >= c.data_limit:
                log_message('info', f"{ip} has exhausted limit. Denying.")
                client_socket.close()
                session_db.close()
                return

            c.port = port
            c.active = True
            c.last_seen = datetime.datetime.utcnow()
            session_db.commit()
    except Exception as e:
        log_message('error', f"DB error with {ip}: {e}")
        client_socket.close()
        session_db.close()
        return
    finally:
        session_db.close()

    if ip not in active_connections:
        active_connections[ip] = []
    active_connections[ip].append(client_socket)

    try:
        client_socket.settimeout(5)
        req_data = client_socket.recv(8192)
        if not req_data:
            raise Exception("No initial data.")
        lines = req_data.split(b"\r\n")
        if not lines:
            raise Exception("Malformed request lines.")
        first_line = lines[0].decode(errors='ignore').split()
        if len(first_line) < 3:
            raise Exception("Incomplete request line.")
        method, target = first_line[0], first_line[1]

        if method.upper() == "CONNECT":
            # HTTPS
            if ":" not in target:
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host, port_s = target.split(":")
            port_i = int(port_s)
            try:
                remote = socket.create_connection((host, port_i))
            except:
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client_socket.settimeout(None)
            remote.settimeout(None)
            t_up = threading.Thread(target=tunnel, args=(client_socket, remote, ip, "src->dst"), daemon=True)
            t_down = threading.Thread(target=tunnel, args=(remote, client_socket, ip, "dst->src"), daemon=True)
            t_up.start()
            t_down.start()
            t_up.join()
            t_down.join()
        else:
            # Plain HTTP
            host = None
            for line in lines:
                l = line.decode(errors='ignore').lower()
                if l.startswith("host:"):
                    host = l.split(":", 1)[1].strip()
                    break
            if not host:
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            try:
                remote = socket.create_connection((host, 80))
            except:
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            remote.sendall(req_data)
            t_up = threading.Thread(target=tunnel, args=(client_socket, remote, ip, "src->dst"), daemon=True)
            t_down = threading.Thread(target=tunnel, args=(remote, client_socket, ip, "dst->src"), daemon=True)
            t_up.start()
            t_down.start()
            t_up.join()
            t_down.join()

    except Exception as e:
        log_message('error', f"Error handling {ip}:{port} => {e}")
    finally:
        client_socket.close()
        session = DBSession()
        try:
            c = session.query(Client).filter(Client.ip == ip).first()
            if c:
                c.active = False
                c.last_seen = datetime.datetime.utcnow()
                session.commit()
        except:
            session.rollback()
        finally:
            session.close()

        if ip in active_connections and client_socket in active_connections[ip]:
            active_connections[ip].remove(client_socket)
            if not active_connections[ip]:
                del active_connections[ip]

        log_message('info', f"Connection closed: {ip}:{port}")

# -----------------------------------------------------------------
# Flask
# -----------------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'super_secret_key_here'

# -------------- TEMPLATES --------------

dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VPN/Proxy Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .navbar {
      background: linear-gradient(135deg, #434343 0%, #000000 100%);
    }
    .card {
      background-color: #1e1e1e;
      border: 1px solid #333;
      color: #cfcfcf;
    }
    .table-dark {
      color: #cfcfcf;
    }
    .btn-outline-light {
      border-color: #fff;
    }
    .form-control {
      background-color: #2b2b2b;
      color: #e0e0e0;
      border: 1px solid #555;
    }
    .gradient-bg {
      background: linear-gradient(135deg, #424242 0%, #1f1f1f 100%);
      color: #fff;
      padding: 15px;
      border-radius: 5px;
      margin-bottom: 1rem;
    }
    .badge {
      background-color: #444;
      color: #fff;
    }
    #search-box {
      margin-bottom: 1rem;
      background-color: #2b2b2b;
      border: 1px solid #555;
      color: #e0e0e0;
    }
    .dropdown-menu {
      background-color: #2b2b2b;
      border: 1px solid #555;
    }
    .dropdown-item {
      color: #fff;
    }
    .dropdown-item:hover {
      background-color: #444;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">VPN/Proxy Server</span>
      <div class="d-flex">
        <a href="{{ url_for('view_log') }}" class="btn btn-sm btn-outline-light me-2">View Log</a>
        <a href="{{ url_for('settings') }}" class="btn btn-sm btn-outline-light me-2">Settings</a>
        <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">Logout</a>
      </div>
    </div>
  </nav>

  <div class="container mt-4">
    <div class="gradient-bg">
      <h4>Connection Info</h4>
      <div class="row">
        <div class="col-md-4">
          <p>Server IP: <strong>{{ server_public_ip }}</strong></p>
          <p>Server Country: <strong>{{ server_country }}</strong></p>
        </div>
        <div class="col-md-4">
          <p>Time Zone: <strong>{{ admin_tz }}</strong></p>
          <p>Proxy Port: <strong>{{ vpn_port }}</strong></p>
        </div>
        <div class="col-md-4">
          <p>Total Bandwidth Used: <strong id="total-used">Loading...</strong></p>
          <p>Total Connected: <strong id="connected-count">0</strong> |
             Disconnected: <strong id="disconnected-count">0</strong></p>
        </div>
      </div>
      <p id="proxy-status">Proxy Status: <span class="fw-bold">Loading...</span></p>
      <div>
        <button class="btn btn-success btn-sm" onclick="controlProxy('start')">Start</button>
        <button class="btn btn-warning btn-sm" onclick="controlProxy('restart')">Restart</button>
        <button class="btn btn-danger btn-sm" onclick="controlProxy('stop')">Stop</button>
      </div>
    </div>

    <h5>Search Clients</h5>
    <input type="text" id="search-box" class="form-control" placeholder="Type to filter by IP, location, etc...">

    <h3>Connected Clients</h3>
    <table class="table table-dark table-striped" id="client-table">
      <thead>
        <tr>
          <th>IP</th>
          <th>Location</th>
          <th>Last Seen</th>
          <th>Usage</th>
          <th>Limit</th>
          <th>Conn / Ban</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
      <!-- populated by JS -->
      </tbody>
    </table>

  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    let refreshInterval = null;
    let isDropdownOpen = false;

    // We'll track if a dropdown is open, then skip table refresh
    document.addEventListener('show.bs.dropdown', function(event){
      isDropdownOpen = true;
    });
    document.addEventListener('hide.bs.dropdown', function(event){
      isDropdownOpen = false;
    });

    function controlProxy(cmd) {
      fetch('/control/' + cmd)
      .then(res => res.json())
      .then(data => {
        alert(data.message);
        updateProxyStatus();
      })
      .catch(err => console.error(err));
    }

    function updateProxyStatus() {
      fetch('/control/status')
      .then(res => res.json())
      .then(d => {
        const el = document.querySelector("#proxy-status span");
        el.innerText = d.running ? "Running" : "Stopped";
      });
    }

    // fetch clients
    function fetchClients() {
      if(isDropdownOpen) {
        // if a dropdown is open, skip updating to allow user to click
        return;
      }
      fetch("/status")
      .then(res => res.json())
      .then(d => {
        const clients = d.clients;
        renderClientsTable(clients);
        applyFilter();
        // also update total stats
        let totalUsedBytes = 0;
        let connectedCount = 0;
        let disconnectedCount = 0;
        clients.forEach(c => {
          let usage = c.total_sent + c.total_received;
          totalUsedBytes += usage;
          // If c.active? We'll do "connected" if c.active = True
          if(c.active){
            connectedCount++;
          } else {
            disconnectedCount++;
          }
        });
        document.getElementById("total-used").innerText = d.total_used_display;
        document.getElementById("connected-count").innerText = connectedCount;
        document.getElementById("disconnected-count").innerText = disconnectedCount;
      })
      .catch(err => console.error(err));
    }

    function renderClientsTable(clients) {
      const tbody = document.querySelector("#client-table tbody");
      tbody.innerHTML = "";
      clients.forEach(c => {
        const used = c.total_sent + c.total_received;
        const usedDisplay = c.used_display;
        const limitDisplay = c.data_limit > 0 ? c.limit_display : "No Limit";
        
        const lastSeen = c.last_seen;

        // Connection Badge
        const connBadge = c.active
          ? '<span class="badge bg-success">Connected</span>'
          : '<span class="badge bg-secondary">Disconnected</span>';

        // Ban Badge
        const banBadge = c.banned
          ? '<span class="badge bg-danger">Banned</span>'
          : '<span class="badge bg-info">Active</span>';

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${c.ip}</td>
          <td>${c.location}</td>
          <td>${lastSeen}</td>
          <td>${usedDisplay}</td>
          <td>${limitDisplay}</td>
          <td>${connBadge}<br>${banBadge}</td>
          <td>
            <div class="dropdown">
              <button class="btn btn-sm btn-info dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                Actions
              </button>
              <ul class="dropdown-menu dropdown-menu-dark">
                <li><a class="dropdown-item" href="#" onclick="goDetails('${c.ip}')">View Details</a></li>
                <li><a class="dropdown-item" href="#" onclick="clientAction('${c.ip}','disconnect')">Disconnect</a></li>
                ${ c.banned
                  ? `<li><a class="dropdown-item" href="#" onclick="clientAction('${c.ip}','unban')">Unban</a></li>`
                  : `<li><a class="dropdown-item" href="#" onclick="clientAction('${c.ip}','ban')">Ban</a></li>` }
                <li><a class="dropdown-item" href="#" onclick="resetUsage('${c.ip}')">Reset Usage</a></li>
                <li><a class="dropdown-item" href="#" onclick="setLimitPrompt('${c.ip}')">Set Limit (MB)</a></li>
              </ul>
            </div>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function goDetails(ip) {
      window.location = '/client/' + ip;
    }

    function clientAction(ip, action){
      fetch('/client_action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: ip, action: action})
      })
      .then(res => res.json())
      .then(d => {
        alert(d.message);
        fetchClients();
      })
      .catch(err => console.error(err));
    }

    function resetUsage(ip){
      if(!confirm("Reset usage for " + ip + "?")) return;
      fetch('/reset_usage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip: ip })
      })
      .then(res => res.json())
      .then(d => {
        alert(d.message);
        fetchClients();
      })
      .catch(err => console.error(err));
    }

    function setLimitPrompt(ip){
      const mbVal = prompt("Enter data limit in MB (0 = no limit):");
      if(mbVal === null) return;
      const mbNum = parseFloat(mbVal);
      if(isNaN(mbNum) || mbNum < 0) {
        alert("Invalid MB value");
        return;
      }
      // convert MB to bytes
      const bytesVal = Math.round(mbNum * 1024 * 1024);
      fetch('/set_limit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip: ip, limit: bytesVal })
      })
      .then(res => res.json())
      .then(d => {
        alert(d.message);
        fetchClients();
      })
      .catch(err => console.error(err));
    }

    function applyFilter(){
      const filterVal = document.getElementById("search-box").value.toLowerCase();
      const rows = document.querySelectorAll("#client-table tbody tr");
      rows.forEach(r => {
        const txt = r.innerText.toLowerCase();
        r.style.display = txt.includes(filterVal) ? "" : "none";
      });
    }
    document.getElementById("search-box").addEventListener("input", applyFilter);

    // intervals
    setInterval(fetchClients, 5000);
    setInterval(updateProxyStatus, 5000);

    window.onload = function(){
      fetchClients();
      updateProxyStatus();
    };
  </script>
</body>
</html>
"""

login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VPN/Proxy Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .card {
      background-color: #1e1e1e;
      border: 1px solid #333;
      color: #cfcfcf;
    }
    .form-control {
      background-color: #2b2b2b;
      color: #e0e0e0;
      border: 1px solid #555;
    }
    .btn-primary {
      background-color: #444;
      border-color: #666;
    }
  </style>
</head>
<body>
  <div class="container mt-5">
    <div class="row justify-content-center">
      <div class="col-md-4">
        <div class="card p-3">
          <h4 class="text-center">Server Login</h4>
          {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
          {% endif %}
          <form method="post" action="/">
            <div class="mb-3">
              <input type="text" name="username" class="form-control" placeholder="Username" required>
            </div>
            <div class="mb-3">
              <input type="password" name="password" class="form-control" placeholder="Password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
"""

client_details_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Client Details - {{ client.ip }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .card {
      background-color: #1e1e1e;
      border: 1px solid #333;
      color: #cfcfcf;
    }
    .navbar {
      background: linear-gradient(135deg, #434343 0%, #000000 100%);
    }
    .chart-container {
      height: 350px;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-dark mb-3">
    <div class="container-fluid">
      <span class="navbar-brand">Client Details</span>
      <button class="btn btn-sm btn-outline-light" onclick="window.location='{{ url_for('dashboard_route') }}'">Dashboard</button>
    </div>
  </nav>
  <div class="container">
    <h2>Client IP: {{ client.ip }}</h2>
    <p><strong>Location:</strong> {{ client.location }}</p>
    <p><strong>Connected Since:</strong> {{ connected_start }}</p>
    <p><strong>Last Seen:</strong> <span id="last-seen">{{ last_seen }}</span></p>
    <p>
      <strong>Data Used:</strong> <span id="used">{{ used_display }}</span>
      {% if client.data_limit > 0 %}
        &nbsp; | <strong>Limit:</strong> <span id="limit">{{ limit_display }}</span>
        &nbsp; | <strong>Remaining:</strong> <span id="remain">{{ remain_display }}</span>
      {% else %}
        &nbsp; | <strong>No Limit</strong>
      {% endif %}
    </p>

    <div class="row">
      <div class="col-md-6">
        <div class="chart-container">
          <canvas id="usageChart"></canvas>
        </div>
      </div>
      <div class="col-md-6">
        {% if client.data_limit > 0 %}
        <div class="chart-container">
          <canvas id="pieChart"></canvas>
        </div>
        {% else %}
        <p>No data limit set, pie chart not shown.</p>
        {% endif %}
      </div>
    </div>
  </div>

  <script>
    let usageChart;
    let pieChart;
    let ip = "{{ client.ip }}";

    function initLineChart(labels, sentData, recvData) {
      const ctx = document.getElementById("usageChart").getContext("2d");
      if(usageChart) usageChart.destroy();
      usageChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Sent (MB)',
              data: sentData,
              borderColor: 'rgba(0,200,255,1)',
              fill: false
            },
            {
              label: 'Received (MB)',
              data: recvData,
              borderColor: 'rgba(255,100,100,1)',
              fill: false
            }
          ]
        },
        options: {
          responsive: true,
          animation: false,  // no animation
          scales: {
            x: { display: true },
            y: {
              display: true,
              beginAtZero: true
            }
          }
        }
      });
    }

    function initPieChart(used, remain) {
      const pctx = document.getElementById("pieChart").getContext("2d");
      if(pieChart) pieChart.destroy();
      pieChart = new Chart(pctx, {
        type: 'pie',
        data: {
          labels: ['Used (MB)', 'Remaining (MB)'],
          datasets: [
            {
              data: [used, remain],
              backgroundColor: ['rgba(255,80,80,0.7)', 'rgba(80,255,80,0.7)']
            }
          ]
        },
        options: {
          responsive: true,
          animation: false  // no animation
        }
      });
    }

    function fetchDetails() {
      fetch("/client_status/" + ip)
      .then(res => res.json())
      .then(d => {
        if(d.message){
          console.log(d.message);
          return;
        }
        document.getElementById("last-seen").innerText = d.last_seen;
        document.getElementById("used").innerText = d.used_display;
        if(d.limit_display){
          document.getElementById("limit").innerText = d.limit_display;
          document.getElementById("remain").innerText = d.remain_display;
        }
        // line chart
        initLineChart(d.log_times, d.log_sent, d.log_recv);
        // pie chart if limit>0
        if(d.limit > 0){
          initPieChart(d.used_mb, d.remain_mb);
        }
      })
      .catch(err => console.error(err));
    }

    setInterval(fetchDetails, 5000);
    window.onload = function(){
      fetchDetails();
    };
  </script>
</body>
</html>
"""

settings_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Server Settings</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .card {
      background-color: #1e1e1e;
      border: 1px solid #333;
      color: #cfcfcf;
    }
    .form-control {
      background-color: #2b2b2b;
      color: #e0e0e0;
      border: 1px solid #555;
    }
    .navbar {
      background: linear-gradient(135deg, #434343 0%, #000000 100%);
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">Settings</span>
      <div>
        <a href="{{ url_for('dashboard_route') }}" class="btn btn-sm btn-outline-light">Back to Dashboard</a>
      </div>
    </div>
  </nav>
  <div class="container mt-4">
    <h3>Server Configuration</h3>
    <p>Note: Some changes might require a proxy or full script restart.</p>
    <form method="post" action="/settings">
      <div class="mb-3">
        <label for="proxyPort" class="form-label">Proxy Port</label>
        <input type="number" class="form-control" id="proxyPort" name="proxy_port" value="{{ proxy_port }}">
      </div>
      <div class="mb-3">
        <label for="httpPort" class="form-label">Dashboard HTTP Port</label>
        <input type="number" class="form-control" id="httpPort" name="http_port" value="{{ http_port }}">
      </div>
      <div class="mb-3">
        <label for="timeZone" class="form-label">Time Zone</label>
        <select class="form-control" id="timeZone" name="time_zone">
          {% for tz in timezones %}
            <option value="{{ tz }}" {% if tz == current_tz %}selected{% endif %}>{{ tz }}</option>
          {% endfor %}
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Save & Restart Proxy</button>
    </form>
  </div>
</body>
</html>
"""

view_log_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Server Log</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #121212;
      color: #e0e0e0;
    }
    .log-container {
      background-color: #1e1e1e;
      border: 1px solid #333;
      padding: 10px;
      height: 600px;
      overflow-y: scroll;
      white-space: pre-wrap;
    }
    .navbar {
      background: linear-gradient(135deg, #434343 0%, #000000 100%);
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">Server Log</span>
      <div>
        <a href="{{ url_for('dashboard_route') }}" class="btn btn-sm btn-outline-light">Dashboard</a>
      </div>
    </div>
  </nav>
  <div class="container mt-3">
    <h4>Recent Log Entries</h4>
    <div class="log-container">{{ log_content }}</div>
  </div>
</body>
</html>
"""

# -------------- Flask Routes --------------

@app.route('/', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == VPN_USERNAME and password == VPN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard_route'))
        else:
            return render_template_string(login_template, error="Invalid credentials!")
    return render_template_string(login_template, error="")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_route'))

@app.route('/dashboard')
def dashboard_route():
    if not session.get('logged_in'):
        return redirect(url_for('login_route'))
    return render_template_string(
        dashboard_template,
        server_public_ip=SERVER_PUBLIC_IP,
        server_country=SERVER_COUNTRY,
        admin_tz=ADMIN_TZ,
        vpn_port=PROXY_TCP_PORT
    )

@app.route('/view_log')
def view_log():
    if not session.get('logged_in'):
        return redirect(url_for('login_route'))
    if not os.path.exists(LOG_FILE):
        content = "No log file found."
    else:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        if len(lines) > 500:
            lines = lines[-500:]
        content = "".join(lines)
    return render_template_string(view_log_template, log_content=content)

@app.route('/status')
def status_route():
    """Return JSON of all clients plus total usage for the top bar."""
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    session_db = DBSession()
    clients = session_db.query(Client).all()
    data_list = []
    total_used = 0
    for c in clients:
        used = c.total_sent + c.total_received
        total_used += used
        data_list.append({
            "ip": c.ip,
            "port": c.port,
            "location": c.location,
            "last_seen": to_admin_tz(c.last_seen),
            "total_sent": c.total_sent,
            "total_received": c.total_received,
            "used_display": bytes_to_mb_or_gb(used),
            "data_limit": c.data_limit,
            "limit_display": bytes_to_mb_or_gb(c.data_limit) if c.data_limit>0 else "",
            "active": c.active,
            "banned": c.banned
        })
    session_db.close()
    return jsonify({
        "clients": data_list,
        "total_used_display": bytes_to_mb_or_gb(total_used)
    })

@app.route('/client/<string:client_ip>')
def client_details(client_ip):
    if not session.get('logged_in'):
        return redirect(url_for('login_route'))
    session_db = DBSession()
    c = session_db.query(Client).filter(Client.ip == client_ip).first()
    if not c:
        session_db.close()
        return f"No client found for IP {client_ip}", 404

    used = c.total_sent + c.total_received
    used_display = bytes_to_mb_or_gb(used)
    limit_display = None
    remain_display = None
    if c.data_limit > 0:
        limit_display = bytes_to_mb_or_gb(c.data_limit)
        remain = c.data_limit - used
        if remain < 0:
            remain = 0
        remain_display = bytes_to_mb_or_gb(remain)

    connected_start = to_admin_tz(c.connection_start)
    last_seen = to_admin_tz(c.last_seen)
    session_db.close()

    return render_template_string(
        client_details_template,
        client=c,
        connected_start=connected_start,
        last_seen=last_seen,
        used_display=used_display,
        limit_display=limit_display,
        remain_display=remain_display
    )

@app.route('/client_status/<string:client_ip>')
def client_status(client_ip):
    """Realtime detail fetch for usage & last logs."""
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    session_db = DBSession()
    c = session_db.query(Client).filter(Client.ip == client_ip).first()
    if not c:
        session_db.close()
        return jsonify({"message": "No client found"}), 404
    used = c.total_sent + c.total_received
    used_display = bytes_to_mb_or_gb(used)

    limit_val = c.data_limit
    limit_display = None
    remain_display = None
    used_mb = round(used / (1024**2), 2)
    remain_mb = 0
    if c.data_limit > 0:
        limit_display = bytes_to_mb_or_gb(c.data_limit)
        remain_val = c.data_limit - used
        if remain_val < 0:
            remain_val = 0
        remain_display = bytes_to_mb_or_gb(remain_val)
        remain_mb = round(remain_val / (1024**2), 2)

    # last 20 logs
    logs = session_db.query(ConnectionLog)\
        .filter(ConnectionLog.client_ip == client_ip)\
        .order_by(ConnectionLog.timestamp.desc())\
        .limit(20).all()
    logs = list(reversed(logs))
    # build arrays
    log_times = [to_admin_tz(l.timestamp) for l in logs]
    log_sent = []
    log_recv = []
    for l in logs:
        s_mb = float(l.sent)/(1024**2)
        r_mb = float(l.received)/(1024**2)
        log_sent.append(round(s_mb, 2))
        log_recv.append(round(r_mb, 2))

    resp = {
        "ip": c.ip,
        "last_seen": to_admin_tz(c.last_seen),
        "used_display": used_display,
        "limit_display": limit_display,
        "remain_display": remain_display,
        "limit": limit_val,
        "used_mb": used_mb,
        "remain_mb": remain_mb,
        "log_times": log_times,
        "log_sent": log_sent,
        "log_recv": log_recv
    }
    session_db.close()
    return jsonify(resp)

@app.route('/client_action', methods=['POST'])
def client_action():
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    data = request.get_json()
    ip = data.get("ip")
    action = data.get("action", "")
    session_db = DBSession()
    c = session_db.query(Client).filter(Client.ip == ip).first()
    if not c:
        session_db.close()
        return jsonify({"message": f"No client found for {ip}"}), 404

    if action == "disconnect":
        if ip in active_connections:
            for sock in active_connections[ip]:
                try:
                    sock.close()
                except:
                    pass
            del active_connections[ip]
        c.active = False
        session_db.commit()
        session_db.close()
        return jsonify({"message": f"Client {ip} forcibly disconnected."})

    elif action == "ban":
        c.banned = True
        if ip in active_connections:
            for sock in active_connections[ip]:
                try:
                    sock.close()
                except:
                    pass
            del active_connections[ip]
        session_db.commit()
        session_db.close()
        return jsonify({"message": f"Client {ip} has been banned."})

    elif action == "unban":
        c.banned = False
        session_db.commit()
        session_db.close()
        return jsonify({"message": f"Client {ip} is unbanned."})

    session_db.close()
    return jsonify({"message": "Unknown action."})

@app.route('/reset_usage', methods=['POST'])
def reset_usage():
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    data = request.get_json()
    ip = data.get("ip")
    session_db = DBSession()
    c = session_db.query(Client).filter(Client.ip == ip).first()
    if not c:
        session_db.close()
        return jsonify({"message": f"No client found for {ip}"}), 404
    c.total_sent = 0
    c.total_received = 0
    session_db.commit()
    session_db.close()
    return jsonify({"message": f"Usage reset for IP {ip}."})

@app.route('/set_limit', methods=['POST'])
def set_limit():
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    data = request.get_json()
    ip = data.get("ip")
    limit_bytes = data.get("limit", 0)
    session_db = DBSession()
    c = session_db.query(Client).filter(Client.ip == ip).first()
    if not c:
        session_db.close()
        return jsonify({"message": f"No client found for {ip}"}), 404
    c.data_limit = limit_bytes
    session_db.commit()
    session_db.close()
    return jsonify({"message": f"Data limit set to {limit_bytes} bytes for {ip}."})

@app.route('/export_csv')
def export_csv():
    if not session.get('logged_in'):
        return redirect(url_for('login_route'))
    session_db = DBSession()
    clients = session_db.query(Client).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP","Location","Last Seen","Total Sent","Total Received","Data Limit","Banned"])
    for c in clients:
        writer.writerow([
            c.ip,
            c.location,
            to_admin_tz(c.last_seen),
            c.total_sent,
            c.total_received,
            c.data_limit,
            c.banned
        ])
    session_db.close()
    output.seek(0)
    resp = make_response(output.read())
    resp.headers["Content-Disposition"] = "attachment; filename=clients.csv"
    resp.headers["Content-Type"] = "text/csv"
    return resp

@app.route('/clear_logs')
def clear_logs():
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    try:
        open(LOG_FILE,'w').close()
        return jsonify({"message": "Server logs cleared."})
    except:
        return jsonify({"message": "Failed to clear logs."}), 500

@app.route('/reset_db')
def reset_db():
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    try:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        return jsonify({"message": "Database reset successfully."})
    except Exception as e:
        return jsonify({"message": f"Failed to reset DB: {e}"}), 500

@app.route('/control/<string:cmd>')
def control_route(cmd):
    if not session.get('logged_in'):
        return jsonify({"message": "Unauthorized"}), 401
    if cmd == 'start':
        ok, msg = start_proxy()
        return jsonify({"running": ok, "message": msg})
    elif cmd == 'stop':
        ok, msg = stop_proxy()
        return jsonify({"running": ok, "message": msg})
    elif cmd == 'restart':
        ok, msg = restart_proxy()
        return jsonify({"running": ok, "message": msg})
    elif cmd == 'status':
        return jsonify({"running": get_proxy_status()})
    return jsonify({"message": "Unknown command."}), 400

@app.route('/settings', methods=['GET','POST'])
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login_route'))
    if request.method == 'POST':
        new_proxy_port = request.form.get("proxy_port","")
        new_http_port  = request.form.get("http_port","")
        new_time_zone  = request.form.get("time_zone","UTC")
        try:
            pport = int(new_proxy_port)
            hport = int(new_http_port)
            config['SERVER']['proxy_tcp_port'] = str(pport)
            config['SERVER']['http_port']      = str(hport)
            config['SERVER']['time_zone']      = new_time_zone
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)
            # apply new proxy port
            stop_proxy()
            global PROXY_TCP_PORT, HTTP_PORT, ADMIN_TZ
            PROXY_TCP_PORT = pport
            HTTP_PORT      = hport
            ADMIN_TZ       = new_time_zone
            start_proxy()
            return (f"<h3>Settings saved.<br>"
                    f"Proxy port = {pport}.<br>"
                    f"Flask port = {hport} (requires manual script restart to actually move dashboard).<br>"
                    f"Time zone = {new_time_zone}</h3>"
                    f"<br><a href='{url_for('dashboard_route')}'>Back</a>")
        except ValueError:
            return "Invalid port values."
    # GET
    return render_template_string(
        settings_template,
        proxy_port=PROXY_TCP_PORT,
        http_port=HTTP_PORT,
        timezones=TIMEZONES_LIST,
        current_tz=ADMIN_TZ
    )

# -----------------------------------------------------------------
# Flask Thread
# -----------------------------------------------------------------
class FlaskThread(threading.Thread):
    def __init__(self, app, port):
        super().__init__()
        self.srv = make_server('0.0.0.0', port, app)
        self.ctx = app.app_context()
        self.ctx.push()
    def run(self):
        log_message('info', f"Dashboard running at http://0.0.0.0:{HTTP_PORT}")
        self.srv.serve_forever()
    def shutdown(self):
        self.srv.shutdown()

# -----------------------------------------------------------------
# Main
# -----------------------------------------------------------------
def main():
    # Start the Flask dashboard
    flask_thread = FlaskThread(app, HTTP_PORT)
    flask_thread.daemon = True
    flask_thread.start()

    log_message('info', f"Web dashboard started on http://0.0.0.0:{HTTP_PORT}")

    # Optionally start proxy automatically
    # start_proxy()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_message('info', "Shutting down...")
        flask_thread.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
