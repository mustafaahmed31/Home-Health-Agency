const express = require("express");
const SftpClient = require("ssh2-sftp-client");

const app = express();
app.use(express.json({ limit: "5mb" }));

const API_KEY = process.env.API_KEY || "";
const DEFAULT_SFTP_HOST = "files.availity.com";
const DEFAULT_SFTP_PORT = 22;

function sanitizeSftpHost(rawHost) {
  const trimmed = String(rawHost || "").trim().replace(/^['"]|['"]$/g, "");
  if (!trimmed) return DEFAULT_SFTP_HOST;
  let host = trimmed.replace(/^sftp:\/\//i, "").replace(/^https?:\/\//i, "");
  host = host.split("/")[0];
  if (host.includes(":")) { host = host.split(":")[0]; }
  return host || DEFAULT_SFTP_HOST;
}

function sanitizeSftpPort(rawPort) {
  const parsed = parseInt(String(rawPort || "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) return DEFAULT_SFTP_PORT;
  return parsed;
}

const SFTP_HOST = sanitizeSftpHost(process.env.SFTP_HOST);
const SFTP_PORT = sanitizeSftpPort(process.env.SFTP_PORT);
const SFTP_USERNAME = (process.env.SFTP_USERNAME || "").trim();
const SFTP_PASSWORD = process.env.SFTP_PASSWORD || "";

async function connectWithFallback(sftp) {
  const connectOptions = {
    host: SFTP_HOST, port: SFTP_PORT, username: SFTP_USERNAME, password: SFTP_PASSWORD,
    readyTimeout: 30000, retries: 3, retry_factor: 2, retry_minTimeout: 2000,
  };
  try {
    await sftp.connect(connectOptions);
    return { host: SFTP_HOST, port: SFTP_PORT, usedFallback: false };
  } catch (error) {
    const message = String(error?.message || "").toLowerCase();
    const dnsLookupFailure = message.includes("address lookup failed") || message.includes("enotfound") || message.includes("getaddrinfo");
    if (!dnsLookupFailure || SFTP_HOST === DEFAULT_SFTP_HOST) throw error;
    console.warn(`[SFTP] Primary host '${SFTP_HOST}' failed DNS lookup; retrying '${DEFAULT_SFTP_HOST}:${DEFAULT_SFTP_PORT}'.`);
    await sftp.connect({ ...connectOptions, host: DEFAULT_SFTP_HOST, port: DEFAULT_SFTP_PORT });
    return { host: DEFAULT_SFTP_HOST, port: DEFAULT_SFTP_PORT, usedFallback: true };
  }
}

function authenticate(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers["x-api-key"];
  if (key !== API_KEY) return res.status(401).json({ success: false, error: "Unauthorized" });
  next();
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.post("/edi", authenticate, async (req, res) => {
  const { action } = req.body;
  if (action === "upload") return handleUpload(req, res);
  if (action === "poll") return handlePoll(req, res);
  return res.status(400).json({ success: false, error: "Unknown action: " + action });
});

async function handleUpload(req, res) {
  const { fileName, ediContent, remotePath } = req.body;
  if (!fileName || !ediContent) return res.status(400).json({ success: false, error: "Missing fileName or ediContent" });
  const sftp = new SftpClient();
  const uploadPath = remotePath || `/SendFiles/${fileName}`;
  try {
    const connection = await connectWithFallback(sftp);
    console.log(`[UPLOAD] Connected to ${connection.host}:${connection.port}${connection.usedFallback ? " (fallback)" : ""}`);
    const fileBuffer = Buffer.from(ediContent, "utf-8");
    await sftp.put(fileBuffer, uploadPath);
    console.log(`[UPLOAD] Success: ${uploadPath} (${fileBuffer.length} bytes)`);
    await sftp.end();
    return res.json({ success: true, remotePath: uploadPath, size: fileBuffer.length });
  } catch (err) {
    console.error("[UPLOAD] Failed:", err.message);
    try { await sftp.end(); } catch (_e) {}
    return res.status(502).json({ success: false, error: err.message });
  }
}

function parseEdiResponseStatus(content, fileName) {
  const contentUpper = content.toUpperCase();
  const ta1Match = contentUpper.match(/TA1\*[^*]*\*[^*]*\*[^*]*\*([ARE])\*/);
  if (ta1Match) {
    if (ta1Match[1] === "A") return "accepted";
    if (ta1Match[1] === "R") return "rejected";
    if (ta1Match[1] === "E") return "accepted_with_errors";
  }
  const ak9Match = contentUpper.match(/AK9\*([AREMWX])/);
  if (ak9Match) {
    if (ak9Match[1] === "A") return "accepted";
    if (ak9Match[1] === "R" || ak9Match[1] === "X") return "rejected";
    return "accepted_with_errors";
  }
  const ak5Match = contentUpper.match(/AK5\*([AREMWX])/);
  if (ak5Match) {
    if (ak5Match[1] === "A") return "accepted";
    if (ak5Match[1] === "R" || ak5Match[1] === "X") return "rejected";
    return "accepted_with_errors";
  }
  if (contentUpper.includes("STC*")) {
    if (contentUpper.match(/STC\*A[13][*:~]/)) return "accepted";
    if (contentUpper.match(/STC\*A[27][*:~]/)) return "rejected";
    if (contentUpper.match(/STC\*A4[*:~]/)) return "accepted_with_errors";
  }
  if (contentUpper.includes("ACCEPTED") && !contentUpper.includes("NOT ACCEPTED")) return "accepted";
  if (contentUpper.includes("REJECTED") || contentUpper.includes("DENIED")) return "rejected";
  console.warn(`[POLL] Could not determine status from file: ${fileName}`);
  return "pending";
}

async function handlePoll(req, res) {
  const { isaControlNumber, batchDate } = req.body;
  const sftp = new SftpClient();
  try {
    const connection = await connectWithFallback(sftp);
    console.log(`[POLL] Connected to ${connection.host}:${connection.port}${connection.usedFallback ? " (fallback)" : ""}`);
    const inboundFiles = await sftp.list("/ReceiveFiles");
    const matchingFiles = inboundFiles.filter((f) => {
      const name = f.name.toLowerCase();
      if (isaControlNumber && name.includes(isaControlNumber.toLowerCase())) return true;
      if (batchDate && name.includes(batchDate)) return true;
      if ((name.includes("999") || name.includes("277") || name.includes("ta1")) && !f.name.startsWith(".")) return true;
      return false;
    });
    const files = matchingFiles.map((f) => ({ name: f.name, size: f.size, modifyTime: f.modifyTime }));
    let responseStatus = "pending";
    let contentPreview = null;
    if (matchingFiles.length > 0) {
      const latest = matchingFiles.sort((a, b) => (b.modifyTime || 0) - (a.modifyTime || 0))[0];
      try {
        const content = (await sftp.get(`/ReceiveFiles/${latest.name}`)).toString();
        contentPreview = content.slice(0, 2000);
        responseStatus = parseEdiResponseStatus(content, latest.name);
        console.log(`[POLL] Parsed status for ${latest.name}: ${responseStatus}`);
      } catch (readErr) {
        console.error(`[POLL] Failed to read ${latest.name}:`, readErr.message);
      }
    }
    await sftp.end();
    console.log(`[POLL] Found ${files.length} matching files, status: ${responseStatus}`);
    return res.json({ success: true, responseStatus, files, contentPreview });
  } catch (err) {
    console.error("[POLL] Failed:", err.message);
    try { await sftp.end(); } catch (_e) {}
    return res.status(502).json({ success: false, error: err.message });
  }
}

const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => { console.log(`EDI SFTP Relay listening on port ${PORT}`); });

async function handleUpload(req, res) {
  const { fileName, ediContent, remotePath } = req.body;
  if (!fileName || !ediContent) {
    return res.status(400).json({ success: false, error: "Missing fileName or ediContent" });
  }
  const sftp = new SftpClient();
  const uploadPath = remotePath || "/SendFiles/" + fileName;
  try {
    await sftp.connect({ host: SFTP_HOST, port: SFTP_PORT, username: SFTP_USERNAME, password: SFTP_PASSWORD, readyTimeout: 30000 });
    const fileBuffer = Buffer.from(ediContent, "utf-8");
    await sftp.put(fileBuffer, uploadPath);
    await sftp.end();
    return res.json({ success: true, remotePath: uploadPath, size: fileBuffer.length });
  } catch (err) {
    try { await sftp.end(); } catch (_e) {}
    return res.status(502).json({ success: false, error: err.message });
  }
}

async function handlePoll(req, res) {
  const { isaControlNumber, batchDate } = req.body;
  const sftp = new SftpClient();
  try {
    await sftp.connect({ host: SFTP_HOST, port: SFTP_PORT, username: SFTP_USERNAME, password: SFTP_PASSWORD, readyTimeout: 30000 });
    const inboundFiles = await sftp.list("/ReceiveFiles");
    const matchingFiles = inboundFiles.filter((f) => {
      const name = f.name.toLowerCase();
      if (isaControlNumber && name.includes(isaControlNumber.toLowerCase())) return true;
      if (batchDate && name.includes(batchDate)) return true;
      if ((name.includes("999") || name.includes("277") || name.includes("ta1")) && !f.name.startsWith(".")) return true;
      return false;
    });
    const files = matchingFiles.map((f) => ({ name: f.name, size: f.size, modifyTime: f.modifyTime }));
    let responseStatus = "pending";
    let contentPreview = null;
    if (matchingFiles.length > 0) {
      const latest = matchingFiles.sort((a, b) => (b.modifyTime || 0) - (a.modifyTime || 0))[0];
      try {
        const content = (await sftp.get("/ReceiveFiles/" + latest.name)).toString();
        contentPreview = content.slice(0, 2000);
        if (content.includes("AK9*A") || content.includes("AK5*A")) responseStatus = "accepted";
        else if (content.includes("AK9*R") || content.includes("AK5*R")) responseStatus = "rejected";
        else if (content.includes("AK9*E") || content.includes("AK5*E")) responseStatus = "accepted_with_errors";
      } catch (readErr) {}
    }
    await sftp.end();
    return res.json({ success: true, responseStatus, files, contentPreview });
  } catch (err) {
    try { await sftp.end(); } catch (_e) {}
    return res.status(502).json({ success: false, error: err.message });
  }
}

const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => { console.log("EDI SFTP Relay listening on port " + PORT); });
