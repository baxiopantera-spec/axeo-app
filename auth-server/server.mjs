import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const BOT_TOKEN = process.env.BOT_TOKEN || "";
const PASSWORD_SECRET = process.env.PASSWORD_SECRET || "";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
const ROTATION_TZ = process.env.ROTATION_TZ || "Europe/Moscow";
const DELETE_AFTER_SEC = Math.max(30, Number(process.env.DELETE_AFTER_SEC || 120));
const ALLOWED_TELEGRAM_IDS = new Set(
  (process.env.ALLOWED_TELEGRAM_IDS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean)
);

const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 20;
const rate = new Map();

const manuals = JSON.parse(await fs.readFile(path.join(__dirname, "manuals.json"), "utf8"));
const catalog = JSON.parse(await fs.readFile(path.join(__dirname, "catalog.json"), "utf8"));

if(!PASSWORD_SECRET) console.warn("WARNING: PASSWORD_SECRET is not set.");
if(!BOT_TOKEN) console.warn("WARNING: BOT_TOKEN is not set; Telegram bot is disabled.");
if(ALLOWED_TELEGRAM_IDS.size === 0) console.warn("WARNING: ALLOWED_TELEGRAM_IDS is empty; no Telegram user can receive passwords.");

function nowParts(date = new Date()){
  const parts = new Intl.DateTimeFormat("en", {
    timeZone: ROTATION_TZ,
    year:"numeric", month:"2-digit", day:"2-digit",
    hour:"2-digit", minute:"2-digit", second:"2-digit",
    hour12:false
  }).formatToParts(date);
  const out = {};
  for(const p of parts){ if(p.type !== "literal") out[p.type] = p.value; }
  return out;
}

function rotationKey(date = new Date()){
  const p = nowParts(date);
  return `${p.year}-${p.month}-${p.day}`;
}

function zonedMidnightToUtc(year, month, day){
  let guess = Date.UTC(year, month - 1, day, 0, 0, 0);
  for(let i = 0; i < 4; i++){
    const p = nowParts(new Date(guess));
    const seen = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour), Number(p.minute), Number(p.second));
    const wanted = Date.UTC(year, month - 1, day, 0, 0, 0);
    guess += wanted - seen;
  }
  return new Date(guess);
}

function nextRotationAt(date = new Date()){
  const p = nowParts(date);
  const d = new Date(Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day) + 1));
  return zonedMidnightToUtc(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
}

function dailyPassword(manualKey, dateKey = rotationKey()){
  if(!PASSWORD_SECRET) throw new Error("PASSWORD_SECRET not configured");
  const digest = crypto.createHmac("sha256", PASSWORD_SECRET).update(`${dateKey}|${manualKey}`).digest();
  let out = "";
  for(let i = 0; i < 12; i++) out += PASSWORD_ALPHABET[digest[i] % PASSWORD_ALPHABET.length];
  return out;
}

function safeEqual(a, b){
  const aa = crypto.createHash("sha256").update(String(a)).digest();
  const bb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(aa, bb);
}

function b64url(v){ return Buffer.from(v).toString("base64url"); }
function tokenFor(manualKey){
  const exp = Math.floor(Math.min(nextRotationAt().getTime(), Date.now() + 60 * 60 * 1000) / 1000);
  const payload = { k: manualKey, exp };
  const raw = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", PASSWORD_SECRET).update(raw).digest("base64url");
  return `${raw}.${sig}`;
}
function verifyToken(token){
  try{
    const [raw, sig] = String(token || "").split(".");
    if(!raw || !sig) return null;
    const expected = crypto.createHmac("sha256", PASSWORD_SECRET).update(raw).digest("base64url");
    if(!safeEqual(sig, expected)) return null;
    const p = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    if(!p.k || !p.exp || p.exp < Math.floor(Date.now() / 1000)) return null;
    return p;
  }catch{return null;}
}

function allowedOrigin(req){
  if(FRONTEND_ORIGIN === "*") return "*";
  const origin = req.headers.origin || "";
  const list = FRONTEND_ORIGIN.split(",").map(x => x.trim()).filter(Boolean);
  return list.includes(origin) ? origin : list[0] || "null";
}
function setCors(req, res){
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin(req));
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}
function json(res, status, data){
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}
async function body(req){
  let data = "";
  for await(const chunk of req) data += chunk;
  return data ? JSON.parse(data) : {};
}
function rateAllowed(req, key){
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").toString().split(",")[0].trim();
  const id = `${ip}|${key}`;
  const now = Date.now();
  const old = rate.get(id);
  if(!old || now - old.window > RATE_WINDOW_MS){ rate.set(id, { window: now, count: 1 }); return true; }
  old.count++;
  return old.count <= RATE_LIMIT;
}

async function telegram(method, payload){
  if(!BOT_TOKEN) throw new Error("BOT_TOKEN not configured");
  const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)
  });
  const j = await r.json();
  if(!j.ok) throw new Error(j.description || `Telegram API error: ${method}`);
  return j.result;
}

function isAllowed(userId){ return ALLOWED_TELEGRAM_IDS.has(String(userId)); }
function privateOnly(message){ return message?.chat?.type === "private"; }

/* =====================================================
   TELEGRAM MENU STRUCTURE
   bank -> direction -> manuals
   Single-manual directions open the password immediately.
===================================================== */

function parseCatalogPath(item){
  const bank = item.display || item.name;
  const rawSub = String(item.sub || "Мануал").trim();

  // Examples:
  // "Классика • 1 мануал" -> direction "Классика", leaf "1 мануал"
  // "ГУ • 2 мануал (ферма)" -> direction "ГУ", leaf "2 мануал (ферма)"
  // "Wildberries" -> direct manual
  const parts = rawSub.split("•").map(x => x.trim()).filter(Boolean);
  if(parts.length >= 2){
    return {bank, direction:parts[0], leaf:parts.slice(1).join(" • ")};
  }
  return {bank, direction:rawSub, leaf:null};
}

const groups = new Map();
for(const item of catalog){
  const parsed = parseCatalogPath(item);
  if(!groups.has(parsed.bank)) groups.set(parsed.bank, new Map());
  const directions = groups.get(parsed.bank);
  if(!directions.has(parsed.direction)) directions.set(parsed.direction, []);
  directions.get(parsed.direction).push({...item, __leaf:parsed.leaf});
}

const bankEntries = [...groups.entries()].map(([name, directions]) => ({ name, directions }));

function bankButtonLabel(name){ return String(name).slice(0, 32); }
function directionButtonLabel(direction){ return String(direction).slice(0, 46); }
function manualButtonLabel(item){
  return String(item.__leaf || item.sub || item.name).slice(0, 46);
}

function mainKeyboard(){
  const rows = [];
  for(let i = 0; i < bankEntries.length; i += 2){
    const row = [];
    for(let j = i; j < Math.min(i + 2, bankEntries.length); j++){
      row.push({ text: bankButtonLabel(bankEntries[j].name), callback_data: `b:${j}` });
    }
    rows.push(row);
  }
  return { inline_keyboard: rows };
}

function bankKeyboard(bankIndex){
  const entry = bankEntries[bankIndex];
  const rows = [];
  let row = [];
  let dIndex = 0;
  for(const [direction, items] of entry.directions.entries()){
    const isSingle = items.length === 1;
    const item = items[0];
    row.push({
      text: directionButtonLabel(direction),
      callback_data: isSingle ? `p:${catalog.indexOf(item)}` : `d:${bankIndex}:${dIndex}`
    });
    dIndex++;
    if(row.length === 2){ rows.push(row); row = []; }
  }
  if(row.length) rows.push(row);
  rows.push([{ text:"← Все банки", callback_data:"m:main" }]);
  return { inline_keyboard: rows };
}

function directionKeyboard(bankIndex, directionIndex){
  const entry = bankEntries[bankIndex];
  const directions = [...entry.directions.entries()];
  const [direction, items] = directions[directionIndex] || [];
  if(!items) return null;
  const rows = [];
  for(let i = 0; i < items.length; i += 2){
    const row = [];
    for(let j = i; j < Math.min(i + 2, items.length); j++){
      const item = items[j];
      row.push({ text: manualButtonLabel(item), callback_data: `p:${catalog.indexOf(item)}` });
    }
    rows.push(row);
  }
  rows.push([
    { text:"← Назад", callback_data:`b:${bankIndex}` },
    { text:"⌂ Банки", callback_data:"m:main" }
  ]);
  return { inline_keyboard: rows };
}

function panelText(){
  return `🔐 <b>AXEO MANUALS</b>\n\nВыберите банк, затем направление и нужный мануал.\n\n<i>Пароль действует до следующей ротации.</i>`;
}
function bankText(entry){
  return `🔐 <b>${escapeHtml(entry.name)}</b>\n\nВыберите направление:`;
}
function directionText(entry, direction){
  return `🔐 <b>${escapeHtml(entry.name)}</b>\n${escapeHtml(direction)}\n\nВыберите мануал:`;
}
function escapeHtml(v){
  return String(v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

async function upsertPanel(chatId, messageId, text, reply_markup){
  const payload = {
    chat_id:chatId,
    message_id:messageId,
    text,
    parse_mode:"HTML",
    reply_markup
  };
  try{
    await telegram("editMessageText", payload);
  }catch(err){
    if(!String(err.message).includes("message is not modified")) throw err;
  }
}

async function sendPassword(chatId, item){
  const pass = dailyPassword(item.key);
  const expires = nextRotationAt();
  const msg = await telegram("sendMessage", {
    chat_id:chatId,
    text:`🔐 <b>Актуальный пароль</b>\n\n<b>${escapeHtml(item.display || item.name)}</b>\n${escapeHtml(item.sub || "Мануал")}\n\nПароль: <code>${pass}</code>\nДействует до: <code>${expires.toLocaleString("ru-RU", {timeZone:ROTATION_TZ})}</code>`,
    parse_mode:"HTML"
  });
  setTimeout(() => telegram("deleteMessage", {chat_id:chatId, message_id:msg.message_id}).catch(() => {}), DELETE_AFTER_SEC * 1000);
}

async function sendMainPanel(chatId){
  return telegram("sendMessage", {
    chat_id:chatId,
    text:panelText(),
    parse_mode:"HTML",
    reply_markup:mainKeyboard()
  });
}

async function handleUpdate(update){
  if(update.callback_query){
    const q = update.callback_query;
    const user = q.from;
    if(!isAllowed(user.id) || q.message?.chat?.type !== "private"){
      await telegram("answerCallbackQuery", {callback_query_id:q.id, text:"Нет доступа", show_alert:true}).catch(() => {});
      return;
    }

    await telegram("answerCallbackQuery", {callback_query_id:q.id}).catch(() => {});
    const data = String(q.data || "");
    const chatId = q.message.chat.id;
    const messageId = q.message.message_id;

    if(data === "m:main"){
      await upsertPanel(chatId, messageId, panelText(), mainKeyboard());
      return;
    }

    if(data.startsWith("b:")){
      const idx = Number(data.slice(2));
      const entry = bankEntries[idx];
      if(!entry) return;

      const allItems = [...entry.directions.values()].flat();
      if(allItems.length === 1){
        // Banks with exactly one manual open the password immediately.
        await sendPassword(chatId, allItems[0]);
        return;
      }

      await upsertPanel(chatId, messageId, bankText(entry), bankKeyboard(idx));
      return;
    }

    if(data.startsWith("d:")){
      const parts = data.split(":");
      const bankIndex = Number(parts[1]);
      const directionIndex = Number(parts[2]);
      const entry = bankEntries[bankIndex];
      if(!entry) return;
      const directions = [...entry.directions.entries()];
      const [direction, items] = directions[directionIndex] || [];
      if(!direction || !items) return;
      await upsertPanel(chatId, messageId, directionText(entry, direction), directionKeyboard(bankIndex, directionIndex));
      return;
    }

    if(data.startsWith("p:")){
      const idx = Number(data.slice(2));
      const item = catalog[idx];
      if(item && manuals[item.key]) await sendPassword(chatId, item);
      return;
    }
    return;
  }

  const msg = update.message;
  if(!msg) return;
  const text = String(msg.text || "").trim();

  if(text === "/id"){
    await telegram("sendMessage", {chat_id:msg.chat.id, text:`Ваш Telegram ID: <code>${msg.from.id}</code>`, parse_mode:"HTML"});
    return;
  }

  if(msg.chat?.type !== "private"){
    if(/^\/(start|pass|passwords|menu|help)/i.test(text)){
      await telegram("sendMessage", {chat_id:msg.chat.id, text:"Для безопасности запрос пароля доступен только в личном чате с ботом."});
    }
    return;
  }

  if(!isAllowed(msg.from.id)){
    await telegram("sendMessage", {chat_id:msg.chat.id, text:"Доступ к служебным паролям не настроен для вашего Telegram ID."});
    return;
  }

  if(/^\/(start|pass|passwords|menu|help)/i.test(text)){
    await sendMainPanel(msg.chat.id);
  }
}

async function botLoop(){
  if(!BOT_TOKEN) return;
  try{
    await telegram("deleteWebhook", {drop_pending_updates:false}).catch(() => {});
    let offset = 0;
    while(true){
      const updates = await telegram("getUpdates", {
        offset,
        timeout:45,
        allowed_updates:["message","callback_query"]
      });
      for(const update of updates){
        offset = update.update_id + 1;
        try{ await handleUpdate(update); }
        catch(err){ console.error("Bot update error", err); }
      }
    }
  }catch(err){
    console.error("Telegram polling stopped:", err.message);
    setTimeout(botLoop, 5000);
  }
}

const server = http.createServer(async(req, res) => {
  setCors(req, res);
  if(req.method === "OPTIONS"){ res.statusCode = 204; res.end(); return; }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if(req.method === "GET" && url.pathname === "/health"){
    json(res, 200, {
      ok:true,
      rotationDate:rotationKey(),
      nextRotationAt:nextRotationAt().toISOString(),
      telegram:!!BOT_TOKEN,
      catalogBanks:bankEntries.length,
      catalogManuals:catalog.length
    });
    return;
  }

  if(req.method === "POST" && url.pathname === "/api/manual/verify"){
    try{
      const data = await body(req);
      const key = String(data.manualKey || "");
      const password = String(data.password || "");
      if(!rateAllowed(req, key)){ json(res,429,{ok:false,error:"RATE_LIMIT"}); return; }
      if(!manuals[key]){ json(res,404,{ok:false,error:"UNKNOWN_MANUAL"}); return; }
      const expected = dailyPassword(key);
      if(!safeEqual(password, expected)){ json(res,401,{ok:false,error:"INVALID_PASSWORD"}); return; }
      json(res,200,{ok:true,token:tokenFor(key),expiresAt:Math.min(nextRotationAt().getTime(),Date.now()+60*60*1000)});
    }catch{
      json(res,400,{ok:false,error:"BAD_REQUEST"});
    }
    return;
  }

  if(req.method === "GET" && url.pathname === "/api/manual/content"){
    const key = url.searchParams.get("key") || "";
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyToken(token);
    if(!payload || payload.k !== key){ json(res,401,{ok:false,error:"UNAUTHORIZED"}); return; }
    const entry = manuals[key];
    if(!entry){ json(res,404,{ok:false,error:"UNKNOWN_MANUAL"}); return; }
    json(res,200,{ok:true,html:entry.html});
    return;
  }

  json(res,404,{ok:false,error:"NOT_FOUND"});
});

server.listen(PORT, () => {
  console.log(`Manual auth server listening on :${PORT}`);
  console.log(`Rotation timezone: ${ROTATION_TZ}`);
  console.log(`Loaded manuals: ${Object.keys(manuals).length}`);
  console.log(`Telegram menu banks: ${bankEntries.length}`);
  console.log(`Telegram menu manuals: ${catalog.length}`);
  botLoop();
});
