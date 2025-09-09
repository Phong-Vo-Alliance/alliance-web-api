// api/contact.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import nodemailer from "nodemailer";
import Busboy from "busboy";

// ---------- CORS ----------
function normalizeOrigin(s?: string) {
  if (!s) return "";
  s = s.trim();
  // bỏ mọi dấu "/" cuối
  s = s.replace(/\/+$/, "");
  // lowercase scheme + host (port giữ nguyên)
  try {
    const u = new URL(s);
    const proto = u.protocol.toLowerCase();
    const host = u.hostname.toLowerCase();
    return `${proto}//${host}${u.port ? `:${u.port}` : ""}`;
  } catch {
    // nếu không parse được URL (vd: thiếu protocol) thì trả về sau khi cắt "/"
    return s.toLowerCase();
  }
}

function setCors(req: VercelRequest, res: VercelResponse) {
  const reqOriginRaw = Array.isArray(req.headers.origin)
    ? req.headers.origin[0]
    : (req.headers.origin as string) || "";

  const reqOrigin = normalizeOrigin(reqOriginRaw);

  const raw = process.env.CORS_ORIGINS || "";
  const allowList = raw
    .split(",")
    .map(s => normalizeOrigin(s))
    .filter(Boolean);

  const isAllowed = allowList.some(rule => {
    if (rule === "*") return true;
    // hỗ trợ wildcard subdomain: http(s)://*.example.com
    if (/^https?:\/\/\*\./.test(rule)) {
      try {
        const r = new URL(rule);
        const u = new URL(reqOrigin);
        const base = r.hostname.replace(/^\*\./, "");
        const host = u.hostname.toLowerCase();
        // khớp đúng domain hoặc subdomain
        const domainOk = host === base || host.endsWith(`.${base}`);
        const protoOk = r.protocol === u.protocol;
        const portOk = !r.port || r.port === u.port; // r.port thường rỗng
        return domainOk && protoOk && portOk;
      } catch { return false; }
    }
    return rule === reqOrigin;
  });

  res.setHeader("Vary", "Origin");
  if (isAllowed) {
    res.setHeader("Access-Control-Allow-Origin", reqOriginRaw); // echo đúng origin client gửi lên
  } else if (process.env.CORS_ORIGINS === "*") {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }

  const acrh = (req.headers["access-control-request-headers"] as string) || "Content-Type";
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", acrh);
}

// ---------- Utils ----------
async function verifyRecaptcha(token: string | undefined) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret || !token) {
    return { ok: false, reason: "missing_secret_or_token" };
  }
  
  // const params = new URLSearchParams();
  // params.append("secret", secret);
  // params.append("response", token);
  // if (ip) params.append("remoteip", ip);
  const params = new URLSearchParams({ secret, response: token });

  try {
    const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = (await resp.json()) as any;

    return {
      ok: !!data.success,
      data,
      reason: Array.isArray(data["error-codes"]) ? data["error-codes"].join(",") : undefined,
    };
  } catch {
    return { ok: false, reason: "recaptcha_failed" };
  }
}
 
function parseAddressList(input?: string | string | string[] | null) {
  if (!input) return undefined;
  if (Array.isArray(input)) return input.filter(Boolean);
  if (typeof input === "string") {
    return input.split(/[;,]+/).map(s => s.trim()).filter(Boolean);
  }
  return undefined;
}

type ParsedForm = {
  fields: Record<string, string>;
  files: Array<{ filename: string; mime: string; data: Buffer }>;
};

function parseMultipart(req: VercelRequest, maxMb = 10): Promise<ParsedForm> {
  return new Promise((resolve, reject) => {
    const bb = Busboy({
      headers: req.headers as any,
      limits: { fileSize: maxMb * 1024 * 1024, files: 5, fields: 100 },
    });

    const fields: Record<string, string> = {};
    const files: Array<{ filename: string; mime: string; data: Buffer }> = [];

    bb.on("field", (name: string, val: string) => {
      fields[name] = val;
    });

    bb.on("file", (_name, file, info) => {
      const { filename, mimeType } = info;
      const chunks: Buffer[] = [];
      file.on("data", (d: Buffer) => chunks.push(d));
      file.on("limit", () => reject(new Error("FILE_TOO_LARGE")));
      file.on("end", () => {
        files.push({ filename, mime: mimeType, data: Buffer.concat(chunks) });
      });
    });

    bb.on("error", reject);
    bb.on("finish", () => resolve({ fields, files }));

    req.pipe(bb);
  });
}

function readJsonBody(req: VercelRequest): Promise<any> {
  // Vercel Node Functions *thường* không parse body sẵn => tự đọc stream an toàn
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", d => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

async function sendMail({
  to, subject, text, html, attachments, cc, bcc, replyTo
}: {
  to: string | string[];
  subject: string;
  text: string;
  html?: string;
  attachments?: any[];
  cc?: string | string[];
  bcc?: string | string[];
  replyTo?: string;
}) {
  const user = process.env.GMAIL_USER!;
  const pass = process.env.GMAIL_APP_PASS!;
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: { user, pass },
  });

  const from = process.env.CONTACT_FROM || user;

  await transporter.sendMail({
    from,
    to: to || process.env.CONTACT_TO || user,
    cc: cc || process.env.CONTACT_CC || "",
    bcc: bcc || process.env.CONTACT_BCC || "",
    replyTo,    
    subject,
    text,
    html,          // thêm HTML
    attachments,   // [{ filename, content: Buffer, contentType }]
  });
}

// ---------- Pretty email content - helper format ----------
const KNOWN_ORDER = [
  "jobTitle",
  "locations",
  "firstName",
  "lastName",
  "email",
  "phone",
  "company",
  "country",
] as const;

const LABELS: Record<string, string> = {
  jobTitle: "Position",
  locations: "Location(s)",
  firstName: "First name",
  lastName: "Last name",
  email: "Email",
  phone: "Phone",
  company: "Company",
  country: "Country",
  // fallback keys sẽ được Title Case tự động
};

function titleCaseKey(k: string) {
  return k
    .replace(/[_-]+/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function stringifyVal(v: any): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function mergeData(primary?: any, fallback?: Record<string, any>) {
  const p = (typeof primary === "object" && primary) ? primary : {};
  const f = (typeof fallback === "object" && fallback) ? fallback : {};
  return { ...f, ...p }; // payload ưu tiên hơn
}

function composeEmailContent(opts: {
  subject: string;
  data: Record<string, any>;
  baseMessage?: string;
  files?: Array<{ filename: string }>;
  ip?: string;
}) {
  const { subject, data, baseMessage, files, ip } = opts;
  const submittedAt = new Date().toISOString().replace("T", " ").replace("Z", " UTC");

  // 1) Sắp xếp field: known trước, unknown sau (alpha)
  const keysKnown = KNOWN_ORDER.filter((k) => data[k] != null && data[k] !== "");
  const keysUnknown = Object.keys(data)
    .filter((k) => !KNOWN_ORDER.includes(k as any) && data[k] != null && data[k] !== "")
    .sort((a, b) => a.localeCompare(b));

  const allKeys = [...keysKnown, ...keysUnknown];

  // 2) Dòng text
  const lines = allKeys.map((k) => {
    const label = LABELS[k] || titleCaseKey(k);
    return `${label}: ${stringifyVal(data[k])}`;
  });

  if (baseMessage && baseMessage.trim()) {
    lines.push("");
    lines.push("Message:");
    lines.push(baseMessage.trim());
  }

  if (files && files.length) {
    lines.push("");
    lines.push(`Attachments: ${files.map((f) => f.filename).join(", ")}`);
  }

  lines.push("");
  lines.push(`Submitted at: ${submittedAt}`);
  if (ip) lines.push(`IP: ${ip}`);

  const text = `${subject}\n\n${lines.join("\n")}`.trim();

  // 3) HTML bảng
  const rows = allKeys
    .map((k) => {
      const label = LABELS[k] || titleCaseKey(k);
      const val = stringifyVal(data[k]);
      return `<tr><td style="padding:8px 12px;border:1px solid #eee;font-weight:600;">${label}</td><td style="padding:8px 12px;border:1px solid #eee;">${val || ""}</td></tr>`;
    })
    .join("");

  // TODO: If we use in the future, message block will be used to make easier in reading
  // const msgBlock = baseMessage && baseMessage.trim()
  //   ? `<tr><td style="padding:8px 12px;border:1px solid #eee;font-weight:600;">Message</td><td style="padding:8px 12px;border:1px solid #eee;white-space:pre-wrap;">${baseMessage
  //       .trim()
  //       .replace(/&/g, "&amp;")
  //       .replace(/</g, "&lt;")
  //       .replace(/>/g, "&gt;")}</td></tr>`
  //   : "";

  const attachBlock =
    files && files.length
      ? `<tr><td style="padding:8px 12px;border:1px solid #eee;font-weight:600;">Attachments</td><td style="padding:8px 12px;border:1px solid #eee;">${files
          .map((f) => f.filename)
          .join(", ")}</td></tr>`
      : "";

  const metaBlock = `
    <tr><td style="padding:8px 12px;border:1px solid #eee;font-weight:600;">Submitted at</td><td style="padding:8px 12px;border:1px solid #eee;">${submittedAt}</td></tr>
    ${ip ? `<tr><td style="padding:8px 12px;border:1px solid #eee;font-weight:600;">IP</td><td style="padding:8px 12px;border:1px solid #eee;">${ip}</td></tr>` : ""}
  `;

  const html = `
  <div style="font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.5;">
    <h2 style="margin:0 0 12px 0;">${subject}</h2>
    <table style="border-collapse:collapse;border:1px solid #eee;">
      ${rows}      
      ${attachBlock}
      ${metaBlock}
    </table>
  </div>`.trim();

  return { text, html };
}


// ---------- Handler ----------
export default async function handler(req: VercelRequest, res: VercelResponse) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  const ct = (req.headers["content-type"] || "").toString();
  const maxMb = Number(process.env.MAX_FILE_MB || 5);

  try {
    let to = "";
    let subject = "";
    let message = "";
    let captchaToken = "";
    let attachments: any[] = [];
    let payloadObj: any = undefined;
    let rawFields: Record<string, any> = {};

    if (ct.startsWith("multipart/form-data")) {
      const { fields, files } = await parseMultipart(req, maxMb);
      rawFields = fields;

      to = fields.to || process.env.CONTACT_TO || "";
      // bạn có thể đổi default subject theo use-case của form:
      subject = fields.subject || "[Alliance Recruitment] New submission";
      message = fields.message || "";
      captchaToken = fields.captchaToken || fields["g-recaptcha-response"] || "";

      if (files.length) {
        attachments = files.map(f => ({
          filename: f.filename,
          content: f.data,
          contentType: f.mime,
        }));
      }

      if (fields.payload) {
        try { payloadObj = JSON.parse(fields.payload); } catch { /* ignore */ }
      }
    } else {
      // JSON
      const body = (req as any).body ?? (await readJsonBody(req));
      rawFields = body;

      to = body.to || process.env.CONTACT_TO || "";
      subject = body.subject || "[Alliance Contact] New submission";
      message = body.message || "";
      captchaToken = body.captchaToken || "";
      // JSON path: no files
      payloadObj = body.payload;
    }

    // ---- Verify reCAPTCHA ----
    const ip =
      (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
      (req.socket && "remoteAddress" in req.socket ? (req.socket as any).remoteAddress : undefined);

    const captcha = await verifyRecaptcha(captchaToken);
    if (!captcha.ok) {
      console.error("reCAPTCHA failed:", captcha.data);
      return res.status(400).json({
        ok: false,
        error: `Invalid reCAPTCHA (${captcha.reason || "unknown"})`,
        meta: {
          hostname: captcha.data?.hostname,
          errors: captcha.data?.["error-codes"],
        },
      });
    }

    // ---- Gộp data để render email đẹp ----
    // - Ưu tiên payload (nếu FE gửi), fallback từ rawFields (để vẫn có firstName...) 
    // - Với CareerApplyForm, payload có: jobTitle, locations, firstName, lastName, email, phone,... 
    // - Với ContactSection/Detail, payload có: firstName, lastName, email, phone, company, country, message (message riêng đã có)
    const dataForEmail = mergeData(payloadObj, {
      jobTitle: rawFields.jobTitle,
      locations: rawFields.locations,
      firstName: rawFields.firstName,
      lastName: rawFields.lastName,
      email: rawFields.email,
      phone: rawFields.phone,
      company: rawFields.company,
      country: rawFields.country,
    });

    const content = composeEmailContent({
      subject,
      data: dataForEmail,
      baseMessage: message,
      files: attachments?.map((a: any) => ({ filename: a.filename })) || [],
      ip,
    });

    // ---- Đọc to/cc/bcc/replyTo và fallback ENV ----
    const toList  = parseAddressList(to || process.env.CONTACT_TO || "");
    const ccList  = parseAddressList(rawFields.cc  || process.env.CONTACT_CC  || "");
    const bccList = parseAddressList(rawFields.bcc || process.env.CONTACT_BCC || "");
    // replyTo ưu tiên theo body/fields, fallback email người gửi (nếu có)
    const replyTo = (rawFields.replyTo || rawFields.email || undefined) as string | undefined;

    if (!toList || toList.length === 0) {
      return res.status(400).json({
        ok: false,
        error: "Missing recipient. Provide 'to' or set CONTACT_TO in environment.",
      });
    }

    // ---- Send mail ----
    await sendMail({
      to: toList || (process.env.CONTACT_TO as string),
      cc: ccList,
      bcc: bccList,
      replyTo,
      subject,
      text: content.text,
      html: content.html,
      attachments,
    });

    return res.status(200).json({ ok: true });
  } catch (err: any) {
    const msg =
      err?.message === "FILE_TOO_LARGE"
        ? `File quá lớn (>${maxMb}MB)`
        : err?.message || "Unknown error";
    return res.status(500).json({ ok: false, error: msg });
  }
}
