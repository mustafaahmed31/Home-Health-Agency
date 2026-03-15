/**
 * EDI SFTP Relay Server
 * 
 * Accepts HTTPS requests from Supabase Edge Functions and forwards
 * EDI files to Availity via SFTP (ftp.availity.com:9922).
 * 
 * Deploy to: Railway, Render, AWS Lambda, or any Node.js host.
 * 
 * Environment variables:
 *   SFTP_HOST       - default: ftp.availity.com
 *   SFTP_PORT       - default: 9922
 *   SFTP_USERNAME   - your Availity SFTP username
 *   SFTP_PASSWORD   - your Availity SFTP password
 *   API_KEY         - shared secret for authenticating requests
 *   PORT            - server port (default: 3000)
 */

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

  let host = trimmed
    .replace(/^sftp:\/\//i, "")
    .replace(/^https?:\/\//i, "");

  host = host.split("/")[0];

  // Handle accidental host:port input in SFTP_HOST
  if (host.includes(":")) {
    host = host.split(":")[0];
  }

  return host || DEFAULT_SFTP_HOST;
}

function sanitizeSftpPort(rawPort) {
  const parsed = parseInt(String(rawPort || "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) {
    return DEFAULT_SFTP_PORT;
  }
  return parsed;
}

const SFTP_HOST = sanitizeSftpHost(process.env.SFTP_HOST);
const SFTP_PORT = sanitizeSftpPort(process.env.SFTP_PORT);
const SFTP_USERNAME = (process.env.SFTP_USERNAME || "").trim();
const SFTP_PASSWORD = process.env.SFTP_PASSWORD || "";

async function connectWithFallback(sftp) {
  const connectOptions = {
    host: SFTP_HOST,
    port: SFTP_PORT,
    username: SFTP_USERNAME,
    password: SFTP_PASSWORD,
    readyTimeout: 30000,
    retries: 3,
    retry_factor: 2,
    retry_minTimeout: 2000,
  };

  try {
    await sftp.connect(connectOptions);
    return { host: SFTP_HOST, port: SFTP_PORT, usedFallback: false };
  } catch (error) {
    const message = String(error?.message || "").toLowerCase();
    const dnsLookupFailure =
      message.includes("address lookup failed") ||
      message.includes("enotfound") ||
      message.includes("getaddrinfo");

    if (!dnsLookupFailure || SFTP_HOST === DEFAULT_SFTP_HOST) {
      throw error;
    }

    console.warn(
      `[SFTP] Primary host '${SFTP_HOST}' failed DNS lookup; retrying '${DEFAULT_SFTP_HOST}:${DEFAULT_SFTP_PORT}'.`
    );

    await sftp.connect({
      ...connectOptions,
      host: DEFAULT_SFTP_HOST,
      port: DEFAULT_SFTP_PORT,
    });

    return { host: DEFAULT_SFTP_HOST, port: DEFAULT_SFTP_PORT, usedFallback: true };
  }
}

// Auth middleware
function authenticate(req, res, next) {
  if (!API_KEY) return next(); // skip if no key configured
  const key = req.headers["x-api-key"];
  if (key !== API_KEY) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  next();
}

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Main endpoint — handles upload and poll actions
app.post("/edi", authenticate, async (req, res) => {
  const { action } = req.body;

  if (action === "upload") {
    return handleUpload(req, res);
  } else if (action === "poll") {
    return handlePoll(req, res);
  } else if (action === "get-content") {
    return handleGetContent(req, res);
  } else {
    return res.status(400).json({ success: false, error: `Unknown action: ${action}` });
  }
});

async function handleUpload(req, res) {
  const { fileName, ediContent, remotePath } = req.body;

  if (!fileName || !ediContent) {
    return res.status(400).json({ success: false, error: "Missing fileName or ediContent" });
  }

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
    try { await sftp.end(); } catch (_e) { /* ignore */ }
    return res.status(502).json({ success: false, error: err.message });
  }
}

/**
 * Parse EDI response content to determine acceptance status.
 * Handles TA1 (Interchange Acknowledgment), 999 (Functional Acknowledgment),
 * and 277CA (Claim Status) response formats.
 */
function parseEdiResponseStatus(content, fileName) {
  const contentUpper = content.toUpperCase();

  // --- TA1 (Interchange Acknowledgment) ---
  const ta1Match = contentUpper.match(/TA1\*[^*]*\*[^*]*\*[^*]*\*([ARE])\*(\d{3})/);
  if (ta1Match) {
    const code = ta1Match[1];
    const errorCode = ta1Match[2];
    const status = code === "A" ? "accepted" : code === "R" ? "rejected" : "accepted_with_errors";
    return { status, errorCode, segment: "TA1", detail: `TA1 status=${code}, error=${errorCode}` };
  }

  // --- 999 Functional Acknowledgment ---
  const ak9Match = contentUpper.match(/AK9\*([AREMWX])/);
  if (ak9Match) {
    const code = ak9Match[1];
    const status = code === "A" ? "accepted" : (code === "R" || code === "X") ? "rejected" : "accepted_with_errors";
    return { status, segment: "AK9", detail: `AK9 status=${code}` };
  }

  const ak5Match = contentUpper.match(/AK5\*([AREMWX])/);
  if (ak5Match) {
    const code = ak5Match[1];
    const status = code === "A" ? "accepted" : (code === "R" || code === "X") ? "rejected" : "accepted_with_errors";
    return { status, segment: "AK5", detail: `AK5 status=${code}` };
  }

  // --- 277CA Claim Acknowledgment ---
  if (contentUpper.includes("STC*")) {
    if (contentUpper.match(/STC\*A[13][*:~]/)) return { status: "accepted", segment: "STC", detail: "277CA accepted" };
    if (contentUpper.match(/STC\*A[27][*:~]/)) return { status: "rejected", segment: "STC", detail: "277CA rejected" };
    if (contentUpper.match(/STC\*A4[*:~]/)) return { status: "accepted_with_errors", segment: "STC", detail: "277CA accepted with errors" };
  }

  // --- Fallback ---
  if (contentUpper.includes("ACCEPTED") && !contentUpper.includes("NOT ACCEPTED")) return { status: "accepted", segment: "text", detail: "Contains ACCEPTED" };
  if (contentUpper.includes("REJECTED") || contentUpper.includes("DENIED")) return { status: "rejected", segment: "text", detail: "Contains REJECTED/DENIED" };

  return { status: "unknown", segment: "none", detail: "Could not parse response format" };
}

/**
 * Extract ISA control number from EDI content.
 * ISA13 is the 13th element in the ISA segment.
 */
function extractIsaControlFromContent(content) {
  const isaMatch = content.match(/ISA(?:\*[^*~]*){12}\*([^*~]+)/i);
  return isaMatch ? isaMatch[1].trim() : null;
}

/**
 * Extract the REFERENCED (original) ISA control from a TA1 acknowledgment.
 * TA1 format: TA1*originalISA13*originalDate*originalTime*ackCode*errorCode~
 */
function extractTa1ReferencedControl(content) {
  const match = content.match(/TA1\*([^*~]+)/i);
  return match ? match[1].trim() : null;
}

async function handlePoll(req, res) {
  const { isaControlNumber, batchDate } = req.body;

  if (!isaControlNumber) {
    return res.status(400).json({ success: false, error: "Missing isaControlNumber for polling" });
  }

  const sftp = new SftpClient();

  try {
    const connection = await connectWithFallback(sftp);
    console.log(`[POLL] Connected to ${connection.host}:${connection.port}${connection.usedFallback ? " (fallback)" : ""}`);
    console.log(`[POLL] Looking for responses matching ISA control: ${isaControlNumber}`);

    const inboundFiles = await sftp.list("/ReceiveFiles");

    // Read each response file and match by ISA control number inside the content
    const responseFiles = [];

    for (const f of inboundFiles) {
      if (f.name.startsWith(".")) continue;
      const nameLower = f.name.toLowerCase();
      // Only look at known response types
      if (!(nameLower.includes("999") || nameLower.includes("277") || nameLower.includes("ta1") || nameLower.endsWith(".edi"))) continue;

      try {
        const content = (await sftp.get(`/ReceiveFiles/${f.name}`)).toString();
        const fileIsa = extractIsaControlFromContent(content);
        const ta1Ref = extractTa1ReferencedControl(content);

        // Match: ISA13 OR TA1-referenced control matches our batch's ISA control
        const normalize = (v) => (v || "").replace(/\s+/g, "").padStart(9, "0");
        const normalizedBatchIsa = normalize((isaControlNumber || "").trim());
        const matchesIsa13 = normalize(fileIsa) === normalizedBatchIsa && !!fileIsa;
        const matchesTa1 = normalize(ta1Ref) === normalizedBatchIsa && !!ta1Ref;
        if (normalizedBatchIsa && (matchesIsa13 || matchesTa1)) {
          const parsed = parseEdiResponseStatus(content, f.name);
          responseFiles.push({
            name: f.name,
            size: f.size,
            modifyTime: f.modifyTime,
            content_preview: content.slice(0, 1000),
            parsed_status: parsed.status,
            error_code: parsed.errorCode || null,
            segment_type: parsed.segment,
            detail: parsed.detail,
          });
          console.log(`[POLL] Matched ${f.name} (ISA: ${fileIsa}) → ${parsed.status}: ${parsed.detail}`);
        }
      } catch (readErr) {
        console.error(`[POLL] Failed to read ${f.name}:`, readErr.message);
      }
    }

    await sftp.end();

    // Determine overall status from individual files
    let overallStatus = "pending";
    if (responseFiles.length > 0) {
      const hasRejected = responseFiles.some(f => f.parsed_status === "rejected");
      const hasAcceptedWithErrors = responseFiles.some(f => f.parsed_status === "accepted_with_errors");
      const allAccepted = responseFiles.every(f => f.parsed_status === "accepted");

      if (hasRejected) overallStatus = "rejected";
      else if (allAccepted) overallStatus = "accepted";
      else if (hasAcceptedWithErrors) overallStatus = "accepted_with_errors";
      else overallStatus = responseFiles[0].parsed_status;
    }

    console.log(`[POLL] Found ${responseFiles.length} matching files, overall: ${overallStatus}`);

    return res.json({
      success: true,
      responseStatus: overallStatus,
      files: responseFiles,
      contentPreview: responseFiles[0]?.content_preview || null,
    });
  } catch (err) {
    console.error("[POLL] Failed:", err.message);
    try { await sftp.end(); } catch (_e) { /* ignore */ }
    return res.status(502).json({ success: false, error: err.message });
  }
}

async function handleGetContent(req, res) {
  const { fileNames } = req.body;
  if (!Array.isArray(fileNames) || fileNames.length === 0) {
    return res.status(400).json({ success: false, error: "Missing fileNames array" });
  }

  const sftp = new SftpClient();
  try {
    const connection = await connectWithFallback(sftp);
    console.log(`[GET-CONTENT] Connected to ${connection.host}:${connection.port}`);

    const results = [];
    for (const fileName of fileNames.slice(0, 10)) {
      try {
        const content = (await sftp.get(`/ReceiveFiles/${fileName}`)).toString();
        const parsed = parseEdiResponseStatus(content, fileName);
        results.push({
          name: fileName,
          content_preview: content.slice(0, 1000),
          parsed_status: parsed.status,
          error_code: parsed.errorCode || null,
          segment_type: parsed.segment,
          detail: parsed.detail,
        });
      } catch (err) {
        console.error(`[GET-CONTENT] Failed to read ${fileName}:`, err.message);
        results.push({ name: fileName, error: err.message });
      }
    }

    await sftp.end();
    return res.json({ success: true, files: results });
  } catch (err) {
    console.error("[GET-CONTENT] Failed:", err.message);
    try { await sftp.end(); } catch (_e) { /* ignore */ }
    return res.status(502).json({ success: false, error: err.message });
  }
}

const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => {
  console.log(`EDI SFTP Relay listening on port ${PORT}`);
});
