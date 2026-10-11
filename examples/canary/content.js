try {
  const root = document.documentElement || document.body;

  const s = document.createElement("script");
  s.src = "https://canary-inject.invalid/x.js";
  root.appendChild(s);

  const f = document.createElement("iframe");
  f.src = "https://canary-frame.invalid/y.html";
  f.style.display = "none";
  root.appendChild(f);

  // Yeu cau service worker beacon NGAY BAY GIO (observer da gan tu lau).
  chrome.runtime.sendMessage({ cmd: "beacon" });
} catch (e) {}

// GD1 provenance validate: content script (isolated world) => phai duoc gan ext_initiated=True
fetch("https://canary-cs.invalid/probe").catch(() => {});