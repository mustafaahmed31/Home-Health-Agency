const express = require("express");
const SftpClient = require("ssh2-sftp-client");

const app = express();
app.use(express.json({ limit: "5mb" }));

const API_KEY = process.env.API_KEY || "";
const SFTP_HOST = process.env.SFTP_HOST || "ftp.availity.com";
const SFTP_PORT = parseInt(process.env.SFTP_PORT || "9922", 10);
const SFTP_USERNAME = process.env.SFTP_USERNAME || "";
const SFTP_PASSWORD = process.env.SFTP_PASSWORD || "";

function authenticate(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers["x-api-key"];
  if (key !== API_KEY) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
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
