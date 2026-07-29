const supabaseClient = window.supabase.createClient(
  SUPABASE_URL,
  SUPABASE_ANON_KEY
);

let sessionKey = null;
let sessionNickname = null;
let replyTarget = null;
let realtimeChannel = null;
const decryptedCache = new Map();

const screenAuth = document.getElementById("screen-auth");
const screenChat = document.getElementById("screen-chat");
const formAuth = document.getElementById("form-auth");
const inputNickname = document.getElementById("input-nickname");
const inputPassword = document.getElementById("input-password");
const authError = document.getElementById("auth-error");
const authSubmit = document.getElementById("auth-submit");
const chatLog = document.getElementById("chat-log");
const formMessage = document.getElementById("form-message");
const inputMessage = document.getElementById("input-message");
const currentNicknameLabel = document.getElementById("current-nickname");
const btnLogout = document.getElementById("btn-logout");
const btnClear = document.getElementById("btn-clear");
const replyBanner = document.getElementById("reply-banner");
const replyBannerText = document.getElementById("reply-banner-text");
const btnCancelReply = document.getElementById("btn-cancel-reply");

function showAuthError(text) {
  authError.textContent = text;
  authError.style.display = text ? "block" : "none";
}

async function checkDeviceBlocked(deviceId) {
  const { data } = await supabaseClient
    .from("login_attempts")
    .select("*")
    .eq("device_id", deviceId)
    .maybeSingle();
  return data;
}

async function registerFailedAttempt(deviceId, existing) {
  if (!existing) {
    await supabaseClient.from("login_attempts").insert({
      device_id: deviceId,
      attempts: 1,
      blocked: false,
    });
    return 1;
  }
  const nextAttempts = existing.attempts + 1;
  const blocked = nextAttempts >= MAX_LOGIN_ATTEMPTS;
  await supabaseClient
    .from("login_attempts")
    .update({ attempts: nextAttempts, blocked, updated_at: new Date().toISOString() })
    .eq("device_id", deviceId);
  return nextAttempts;
}

formAuth.addEventListener("submit", async (e) => {
  e.preventDefault();
  showAuthError("");
  authSubmit.disabled = true;
  authSubmit.textContent = "checking...";

  try {
    const nickname = inputNickname.value.trim();
    const password = inputPassword.value;

    if (!nickname || nickname.length < 2 || nickname.length > 24) {
      showAuthError("name must be 2-24 characters");
      return;
    }
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(nickname)) {
      showAuthError("name: letters, numbers, _ - . only");
      return;
    }
    if (!password) {
      showAuthError("enter password");
      return;
    }

    const deviceId = await getDeviceId();
    const existingAttempt = await checkDeviceBlocked(deviceId);

    if (existingAttempt && existingAttempt.blocked) {
      showAuthError("device blocked");
      return;
    }

    const passwordHash = await sha256Hex(password);
    if (passwordHash !== INVITE_PASSWORD_HASH) {
      const attempts = await registerFailedAttempt(deviceId, existingAttempt);
      const remaining = MAX_LOGIN_ATTEMPTS - attempts;
      if (remaining <= 0) {
        showAuthError("wrong password. device blocked");
      } else {
        showAuthError(`wrong password. attempts left: ${remaining}`);
      }
      return;
    }

    const { data: existingUser } = await supabaseClient
      .from("users")
      .select("nickname, device_id")
      .eq("nickname", nickname)
      .maybeSingle();

    if (!existingUser) {
      await supabaseClient.from("users").insert({
        nickname,
        device_id: deviceId,
      });
    }

    sessionKey = await deriveKeyFromPassword(password);
    sessionNickname = nickname;
    sessionStorage.setItem("anon_nickname", nickname);

    enterChat();
  } catch (err) {
    showAuthError("connection error");
  } finally {
    authSubmit.disabled = false;
    authSubmit.textContent = "login";
  }
});

function enterChat() {
  screenAuth.style.display = "none";
  screenChat.style.display = "flex";
  currentNicknameLabel.textContent = sessionNickname;
  loadMessages();
  subscribeRealtime();
}

function formatTimestamp(iso) {
  const d = new Date(iso);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function renderMessage(msg, messagesById) {
  if (decryptedCache.has(msg.id)) {
    return buildMessageNode(msg, decryptedCache.get(msg.id), messagesById);
  }
  const plaintext = await decryptMessage(sessionKey, msg.ciphertext, msg.iv);
  decryptedCache.set(msg.id, plaintext);
  return buildMessageNode(msg, plaintext, messagesById);
}

function buildMessageNode(msg, plaintext, messagesById) {
  const wrapper = document.createElement("div");
  wrapper.className = "message";
  wrapper.dataset.id = msg.id;

  let replyHtml = "";
  if (msg.reply_to && messagesById.has(msg.reply_to)) {
    const parent = messagesById.get(msg.reply_to);
    const parentText = decryptedCache.get(parent.id) || "";
    const preview = parentText.length > 60 ? parentText.slice(0, 60) + "…" : parentText;
    replyHtml = `<div class="message-reply-ref">&gt; ${escapeHtml(parent.nickname)}: ${escapeHtml(
      preview
    )}</div>`;
  }

  wrapper.innerHTML = `
    <div class="message-head">
      <span class="message-nick">${escapeHtml(msg.nickname)}</span>
      <span class="message-time">${formatTimestamp(msg.created_at)}</span>
    </div>
    ${replyHtml}
    <div class="message-body">${escapeHtml(plaintext)}</div>
    <button class="message-reply-btn" data-id="${msg.id}">reply</button>
  `;

  wrapper.querySelector(".message-reply-btn").addEventListener("click", () => {
    setReplyTarget(msg.id, msg.nickname, plaintext);
  });

  return wrapper;
}

function setReplyTarget(id, nickname, plaintext) {
  replyTarget = id;
  const preview = plaintext.length > 50 ? plaintext.slice(0, 50) + "…" : plaintext;
  replyBannerText.textContent = `${nickname}: ${preview}`;
  replyBanner.style.display = "flex";
  inputMessage.focus();
}

btnCancelReply.addEventListener("click", () => {
  replyTarget = null;
  replyBanner.style.display = "none";
});

let allMessages = [];

async function loadMessages() {
  const { data, error } = await supabaseClient
    .from("messages")
    .select("*")
    .order("created_at", { ascending: true })
    .limit(200);

  if (error) return;
  allMessages = data;
  await rerenderAll();
}

async function rerenderAll() {
  const messagesById = new Map(allMessages.map((m) => [m.id, m]));
  chatLog.innerHTML = "";
  for (const msg of allMessages) {
    const node = await renderMessage(msg, messagesById);
    chatLog.appendChild(node);
  }
  chatLog.scrollTop = chatLog.scrollHeight;
}

function subscribeRealtime() {
  realtimeChannel = supabaseClient
    .channel("messages-realtime")
    .on(
      "postgres_changes",
      { event: "INSERT", schema: "public", table: "messages" },
      async (payload) => {
        allMessages.push(payload.new);
        const messagesById = new Map(allMessages.map((m) => [m.id, m]));
        const node = await renderMessage(payload.new, messagesById);
        const wasAtBottom =
          chatLog.scrollHeight - chatLog.scrollTop - chatLog.clientHeight < 80;
        chatLog.appendChild(node);
        if (wasAtBottom) chatLog.scrollTop = chatLog.scrollHeight;
      }
    )
    .subscribe();
}

formMessage.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = inputMessage.value.trim();
  if (!text) return;

  const { ciphertext, iv } = await encryptMessage(sessionKey, text);

  const { error } = await supabaseClient.from("messages").insert({
    nickname: sessionNickname,
    ciphertext,
    iv,
    reply_to: replyTarget,
  });

  if (!error) {
    inputMessage.value = "";
    replyTarget = null;
    replyBanner.style.display = "none";
  }
});

btnClear.addEventListener("click", () => {
  chatLog.innerHTML = "";
});

btnLogout.addEventListener("click", () => {
  sessionKey = null;
  sessionNickname = null;
  replyTarget = null;
  allMessages = [];
  decryptedCache.clear();
  sessionStorage.removeItem("anon_nickname");
  if (realtimeChannel) supabaseClient.removeChannel(realtimeChannel);
  chatLog.innerHTML = "";
  screenChat.style.display = "none";
  screenAuth.style.display = "flex";
  inputPassword.value = "";
  formAuth.reset();
});
