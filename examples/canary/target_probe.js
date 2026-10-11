// Chi chay khi target_matched spoof canary-target.invalid => beacon toi host rieng
// de smoke xac nhan phase da doc manifest + spoof + tiem content script dung.
fetch("https://canary-target-hit.invalid/probe", { method: "GET" }).catch(() => {});
