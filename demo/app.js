const $ = (selector) => document.querySelector(selector);
const messages = $("#messages");
const input = $("#message-input");
const sendButton = $("#send-button");
const form = $("#chat-form");
const connection = $("#connection");
const connectionLabel = $("#connection-label");

const details = {
  rate: ["01 / 05", "Rate limit", "Giới hạn số lượt hỏi của từng phiên trong cửa sổ 60 giây để giảm spam và lạm dụng tài nguyên. Nếu vượt ngưỡng, yêu cầu dừng tại đây trước khi đến model.", "TRƯỚC MODEL"],
  input: ["02 / 05", "Input guardrail", "Chuẩn hóa Unicode, phát hiện chỉ dẫn ghi đè quy tắc và chỉ cho phép câu hỏi thuộc chủ đề ngân hàng. Yêu cầu bị chặn sẽ không đến Blue model.", "TRƯỚC MODEL"],
  model: ["03 / 05", "Blue model", "Câu hỏi hợp lệ được gửi đến Blue trên OpenRouter. Đây là model cố định của lab; giao diện không lưu hoặc gửi API key từ trình duyệt.", "OPENROUTER"],
  output: ["04 / 05", "Output guardrail", "Bộ lọc che số điện thoại, email, CCCD, API key và mật khẩu trong câu trả lời. Demo thêm một kiểm tra cuối với secret mẫu trước khi hiển thị.", "SAU MODEL"],
  audit: ["05 / 05", "Audit + monitor", "Ghi nhận quyết định của từng lượt hỏi và cập nhật số liệu trong bộ nhớ của phiên chạy demo. Các artifact chấm điểm trong outputs/ không bị ghi đè.", "QUAN SÁT"],
};

function selectStep(name) {
  document.querySelectorAll(".flow-step").forEach((step) => step.classList.toggle("active", step.dataset.step === name));
  const [number, title, copy, tag] = details[name];
  $("#detail-number").textContent = number;
  $("#detail-title").textContent = title;
  $("#detail-copy").textContent = copy;
  $("#detail-tag").textContent = tag;
}
document.querySelectorAll(".flow-step").forEach((step) => step.addEventListener("click", () => selectStep(step.dataset.step)));

function setConnection(ready, label) {
  connection.classList.toggle("ready", ready);
  connection.classList.toggle("error", !ready);
  connectionLabel.textContent = label;
}

function addMessage(role, text, feedback = "", feedbackClass = "") {
  const row = document.createElement("div");
  row.className = `message-row ${role}`;
  if (role === "bot") {
    const avatar = document.createElement("span");
    avatar.className = "message-avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = "B";
    row.append(avatar);
  }
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text;
  row.append(bubble);
  messages.append(row);
  if (feedback) {
    const note = document.createElement("p");
    note.className = `message-feedback ${feedbackClass}`;
    note.textContent = feedback;
    messages.append(note);
  }
  messages.scrollTop = messages.scrollHeight;
  return row;
}

function setState(name, label, type) {
  const target = $(`#state-${name}`);
  target.textContent = label;
  target.className = `step-state ${type}`;
}
function updateFlow(result) {
  for (const name of ["rate", "input", "model", "output", "audit"]) setState(name, "Chưa chạy", "");
  if (result.layer === "rate_limiter") {
    setState("rate", "Đã chặn", "blocked");
    for (const name of ["input", "model", "output"]) setState(name, "Bỏ qua", "skipped");
  } else if (result.layer === "input_guardrail") {
    setState("rate", "Đã qua", "passed");
    setState("input", "Đã chặn", "blocked");
    for (const name of ["model", "output"]) setState(name, "Bỏ qua", "skipped");
  } else {
    setState("rate", "Đã qua", "passed");
    setState("input", "Đã qua", "passed");
    setState("model", result.model_called ? "Đã gọi" : "Bỏ qua", result.model_called ? "passed" : "skipped");
    setState("output", result.layer === "response_boundary" ? "Đã chặn" : result.redacted ? "Đã che" : "Đã qua", result.layer === "response_boundary" ? "blocked" : "passed");
  }
  setState("audit", "Đã ghi", "passed");
  if (result.layer === "rate_limiter") selectStep("rate");
  else if (result.layer === "input_guardrail") selectStep("input");
  else if (result.layer === "response_boundary" || result.redacted) selectStep("output");
  else selectStep("audit");
}

function updateMetrics(metrics) {
  if (!metrics) return;
  $("#request-total").textContent = String(metrics.total_requests || 0).padStart(2, "0");
  $("#blocked-total").textContent = String(metrics.blocked_requests || 0).padStart(2, "0");
}

function sessionId() {
  let value = sessionStorage.getItem("blue-demo-session");
  if (!value) {
    value = `web-${crypto.randomUUID()}`;
    sessionStorage.setItem("blue-demo-session", value);
  }
  return value;
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("status unavailable");
    const status = await response.json();
    setConnection(status.configured, status.configured ? "Blue sẵn sàng" : "Thiếu API key");
    $("#model-label").textContent = status.model;
    updateMetrics(status.metrics);
  } catch {
    setConnection(false, "Mất kết nối");
  }
}

async function sendMessage(message) {
  addMessage("user", message);
  input.value = "";
  input.style.height = "auto";
  sendButton.disabled = true;
  const loading = addMessage("bot", "Đang xử lý…");
  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, user_id: sessionId() }),
    });
    const data = await response.json();
    loading.remove();
    if (!response.ok) {
      addMessage("bot", data.error || "Không thể kết nối với Blue.");
      if (response.status === 503) setConnection(false, "Thiếu API key");
      return;
    }
    const feedback = data.decision === "blocked" ? `Đã chặn tại ${data.layer} · ${data.request_id}` : data.decision === "redacted" ? `Đã che dữ liệu nhạy cảm · ${data.request_id}` : `Đã qua các lớp bảo vệ · ${data.request_id}`;
    addMessage("bot", data.reply, feedback, data.decision);
    $("#model-label").textContent = data.model;
    updateFlow(data);
    updateMetrics(data.metrics);
    setConnection(true, "Blue sẵn sàng");
  } catch {
    loading.remove();
    addMessage("bot", "Không thể kết nối với máy chủ demo. Hãy kiểm tra cửa sổ chạy Blue.");
    setConnection(false, "Mất kết nối");
  } finally {
    sendButton.disabled = false;
    input.focus();
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const message = input.value.trim();
  if (message && !sendButton.disabled) sendMessage(message);
});
input.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    form.requestSubmit();
  }
});
input.addEventListener("input", () => {
  input.style.height = "auto";
  input.style.height = `${Math.min(input.scrollHeight, 100)}px`;
});
document.querySelectorAll("[data-prompt]").forEach((button) => button.addEventListener("click", () => {
  input.value = button.dataset.prompt;
  input.focus();
  input.dispatchEvent(new Event("input"));
}));
refreshStatus();
