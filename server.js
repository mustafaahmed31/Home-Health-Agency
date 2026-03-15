/**
 * EDI SFTP Relay Server
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
    await sf
