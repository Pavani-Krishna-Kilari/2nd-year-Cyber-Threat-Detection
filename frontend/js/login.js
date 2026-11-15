/**
 * AI-SIEM SOC - PREMIUM LOGIN CONTROLLER
 * Updated API integration for Render deployment
 */

const API_BASE = "https://ai-siem-soc.onrender.com";

document.addEventListener("DOMContentLoaded", () => {
  initParticleNetwork();
  initCyberGlobe();
  initInputInteractions();
  initPasswordToggle();
  initLoginForm();
  initModals();
  checkRememberedUser();
});

// ============================================================
// 1. CENTRAL API REQUEST HANDLER
// ============================================================

async function apiRequest(endpoint, options = {}) {
  let response;

  try {
    response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.body
          ? { "Content-Type": "application/json" }
          : {}),
        ...options.headers
      }
    });
  } catch (error) {
    throw new Error(
      "Cannot connect to the backend. Check backend availability and CORS configuration."
    );
  }

  const contentType = response.headers.get("content-type") || "";
  const rawText = await response.text();

  let data = {};

  if (rawText.trim()) {
    try {
      data = JSON.parse(rawText);
    } catch {
      if (!response.ok) {
        throw new Error(
          `Backend error (${response.status}). The server returned a non-JSON response.`
        );
      }

      throw new Error(
        `Invalid backend response. Expected JSON but received: ${rawText.slice(0, 120)}`
      );
    }
  }

  if (!response.ok) {
    const detail =
      data.detail ||
      data.message ||
      data.error ||
      `Request failed with status ${response.status}`;

    throw new Error(
      typeof detail === "string" ? detail : JSON.stringify(detail)
    );
  }

  if (!contentType.includes("application/json") && rawText.trim()) {
    console.warn("Backend response has an unexpected Content-Type:", contentType);
  }

  return data;
}

// ============================================================
// 2. PARTICLE NETWORK BACKGROUND
// ============================================================

function initParticleNetwork() {
  const canvas = document.getElementById("networkCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let width = 0;
  let height = 0;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }

  resize();
  window.addEventListener("resize", resize);

  const mouse = { x: null, y: null, radius: 140 };

  window.addEventListener("mousemove", e => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener("mouseleave", () => {
    mouse.x = null;
    mouse.y = null;
  });

  const colors = ["#00E5FF", "#8B35FF", "#287BFF", "#00B4D8"];

  const particles = [];

  const particleCount = Math.min(
    Math.floor((width * height) / 18000),
    75
  );

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.65,
      vy: (Math.random() - 0.5) * 0.65,
      radius: Math.random() * 2 + 1,
      color: colors[Math.floor(Math.random() * colors.length)]
    });
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);

    particles.forEach((p, i) => {
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      if (p.y > height) p.y = 0;

      if (mouse.x !== null) {
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const distance = Math.hypot(dx, dy);

        if (distance > 0 && distance < mouse.radius) {
          const force = (mouse.radius - distance) / mouse.radius;
          p.x -= (dx / distance) * force * 1.5;
          p.y -= (dy / distance) * force * 1.5;
        }
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowBlur = 8;
      ctx.shadowColor = p.color;
      ctx.fill();
      ctx.shadowBlur = 0;

      for (let j = i + 1; j < particles.length; j++) {
        const other = particles[j];
        const distance = Math.hypot(
          p.x - other.x,
          p.y - other.y
        );

        if (distance < 135) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(other.x, other.y);
          ctx.strokeStyle = p.color;
          ctx.globalAlpha = (1 - distance / 135) * 0.25;
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }
    });

    if (mouse.x !== null) {
      particles.forEach(p => {
        const distance = Math.hypot(
          mouse.x - p.x,
          mouse.y - p.y
        );

        if (distance < 120) {
          ctx.beginPath();
          ctx.moveTo(mouse.x, mouse.y);
          ctx.lineTo(p.x, p.y);
          ctx.strokeStyle = "#00E5FF";
          ctx.globalAlpha = 0.4;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      });
    }

    requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);
}

// ============================================================
// 3. CYBER GLOBE ANIMATION
// ============================================================

function initCyberGlobe() {
  const canvas = document.getElementById("globeCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let width, height, cx, cy, radius;
  let rotation = 0;

  function resize() {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    width = rect.width;
    height = rect.height;

    canvas.width = width * dpr;
    canvas.height = height * dpr;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    cx = width / 2;
    cy = height + 40;
    radius = Math.min(width * 0.65, 230);
  }

  resize();
  window.addEventListener("resize", resize);

  const hubs = [
    [0.70, -1.29],
    [0.90, -2.13],
    [0.90, 0.00],
    [0.62, 0.65],
    [0.62, 1.35],
    [0.61, 2.43],
    [0.23, 1.81],
    [-0.59, 2.64]
  ];

  const arcs = [
    [0, 2], [2, 5], [1, 5], [2, 4]
  ];

  function project(lat, lon) {
    const x = radius * Math.cos(lat) * Math.sin(lon + rotation);
    const y0 = -radius * Math.sin(lat);
    const z = radius * Math.cos(lat) * Math.cos(lon + rotation);

    return {
      x: cx + x,
      y: cy + y0 * Math.cos(0.22) - z * Math.sin(0.22),
      z,
      visible: z > -radius * 0.2
    };
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);
    rotation += 0.006;

    const gradient = ctx.createRadialGradient(
      cx, cy, radius * 0.7,
      cx, cy, radius * 1.1
    );

    gradient.addColorStop(0, "rgba(0,229,255,0)");
    gradient.addColorStop(0.85, "rgba(0,229,255,0.12)");
    gradient.addColorStop(1, "rgba(139,53,255,0)");

    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(cx, cy, radius * 1.1, 0, Math.PI * 2);
    ctx.fill();

    // Latitude lines
    [-0.8, -0.4, 0, 0.4, 0.8].forEach(lat => {
      ctx.beginPath();
      let started = false;

      for (let lon = 0; lon <= Math.PI * 2; lon += 0.15) {
        const p = project(lat, lon);

        if (p.visible) {
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        } else {
          started = false;
        }
      }

      ctx.strokeStyle = "rgba(0,229,255,0.22)";
      ctx.stroke();
    });

    // Longitude lines
    for (let i = 0; i < 12; i++) {
      ctx.beginPath();
      let started = false;
      const lon = i * Math.PI / 6;

      for (let lat = -Math.PI / 2; lat <= Math.PI / 2; lat += 0.12) {
        const p = project(lat, lon);

        if (p.visible) {
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        } else {
          started = false;
        }
      }

      ctx.strokeStyle = "rgba(40,123,255,0.18)";
      ctx.stroke();
    }

    const points = hubs.map(h => project(h[0], h[1]));

    // Network hubs
    points.forEach((p, i) => {
      if (!p.visible || p.z <= 0) return;

      const pulse = 4 + (Math.sin(rotation * 5 + i) + 1) * 2.5;

      ctx.beginPath();
      ctx.arc(p.x, p.y, pulse, 0, Math.PI * 2);
      ctx.strokeStyle = "#00E5FF";
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = "#FFFFFF";
      ctx.shadowBlur = 10;
      ctx.shadowColor = "#00E5FF";
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // Traveling telemetry arcs
    arcs.forEach((arc, i) => {
      const p1 = points[arc[0]];
      const p2 = points[arc[1]];

      if (!p1.visible || !p2.visible) return;

      const t = (rotation * (0.12 + i * 0.015)) % 1;
      const midX = (p1.x + p2.x) / 2;
      const midY = (p1.y + p2.y) / 2 - 25;

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.quadraticCurveTo(midX, midY, p2.x, p2.y);
      ctx.strokeStyle = "rgba(139,53,255,0.35)";
      ctx.stroke();

      const x = (1-t)*(1-t)*p1.x + 2*(1-t)*t*midX + t*t*p2.x;
      const y = (1-t)*(1-t)*p1.y + 2*(1-t)*t*midY + t*t*p2.y;

      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = "#00E5FF";
      ctx.shadowBlur = 10;
      ctx.shadowColor = "#00E5FF";
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);
}

// ============================================================
// 4. INPUT INTERACTIONS
// ============================================================

function initInputInteractions() {
  document.querySelectorAll(".form-input").forEach(input => {
    const container = input.closest(".input-container");
    if (!container) return;

    input.addEventListener("focus", () => {
      container.classList.add("focused");
    });

    input.addEventListener("blur", () => {
      container.classList.remove("focused");
    });
  });
}

// ============================================================
// 5. PASSWORD TOGGLE
// ============================================================

function initPasswordToggle() {
  const button = document.getElementById("btnTogglePassword");
  const password = document.getElementById("inputPassword");
  const eye = document.getElementById("iconEye");
  const eyeOff = document.getElementById("iconEyeOff");

  if (!button || !password) return;

  button.addEventListener("click", () => {
    const show = password.type === "password";

    password.type = show ? "text" : "password";

    if (eye) eye.style.display = show ? "none" : "block";
    if (eyeOff) eyeOff.style.display = show ? "block" : "none";

    button.title = show ? "Hide Password" : "Show Password";
    password.focus();
  });
}

// ============================================================
// 6. ALERT HANDLING
// ============================================================

function showAlert(message, type = "error") {
  const box = document.getElementById("alertBox");
  const msg = document.getElementById("alertMessage");
  const icon = document.getElementById("alertIcon");

  if (!box || !msg) return;

  box.className = `alert-box ${type} show`;
  msg.textContent = message;

  if (icon) {
    icon.textContent =
      type === "error" ? "⛔" :
      type === "success" ? "🛡️" : "ℹ️";
  }
}

function hideAlert() {
  const box = document.getElementById("alertBox");
  if (box) box.className = "alert-box";
}

function setBtnLoading(loading) {
  const button = document.getElementById("btnLogin");
  const text = document.getElementById("btnLoginText");
  const spinner = document.getElementById("btnLoginSpinner");

  if (!button) return;

  button.disabled = loading;

  if (text) text.style.display = loading ? "none" : "flex";
  if (spinner) spinner.style.display = loading ? "block" : "none";
}

// ============================================================
// 7. LOGIN AUTHENTICATION
// ============================================================

let isTransitioning = false;

function initLoginForm() {
  const form = document.getElementById("loginForm");
  const emailInput = document.getElementById("inputEmail");
  const passwordInput = document.getElementById("inputPassword");
  const rememberCheckbox = document.getElementById("checkRememberMe");
  const quickFill = document.getElementById("btnQuickFill");

  if (quickFill) {
    quickFill.addEventListener("click", () => {
      if (emailInput) emailInput.value = "admin@soc.ai";

      if (passwordInput) {
        passwordInput.value = "";
      }

      showAlert(
        "Enter your authorized account password to continue.",
        "info"
      );
    });
  }

  if (!form || !emailInput || !passwordInput) return;

  form.addEventListener("submit", async event => {
    event.preventDefault();

    if (isTransitioning) return;

    hideAlert();

    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const rememberMe = rememberCheckbox?.checked || false;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      showAlert("Please enter a valid email address.");
      emailInput.focus();
      return;
    }

    if (!password) {
      showAlert("Please enter your password.");
      passwordInput.focus();
      return;
    }

    setBtnLoading(true);

    try {
      const data = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          remember_me: rememberMe
        })
      });

      if (!data.session_token) {
        throw new Error(
          "Login response did not contain a session token. Check the backend response format."
        );
      }

      const storage = rememberMe ? localStorage : sessionStorage;

      storage.setItem("siem_auth_token", data.session_token);
      storage.setItem("siem_operator", JSON.stringify(data.user || {}));

      if (rememberMe) {
        localStorage.setItem("siem_remembered_email", email);
      } else {
        localStorage.removeItem("siem_remembered_email");
        localStorage.removeItem("siem_auth_token");
        localStorage.removeItem("siem_operator");
      }

      showAlert(
        data.message || "Authentication successful. Welcome to AI-SIEM SOC.",
        "success"
      );

      playSuccessTransitionAndRedirect();

    } catch (error) {
      console.error("Login error:", error);
      showAlert(error.message || "Authentication failed.");
      setBtnLoading(false);
    }
  });
}

// ============================================================
// 8. SUCCESS TRANSITION
// ============================================================

function playSuccessTransitionAndRedirect() {
  if (isTransitioning) return;
  isTransitioning = true;

  const card = document.querySelector(".login-glass-card");
  const overlay = document.getElementById("loginSuccessOverlay");
  const video = document.getElementById("loginSuccessVideo");
  const stage = document.getElementById("dashboardStage");
  const frame = document.getElementById("dashboardStageFrame");

  if (card) {
    card.style.transition = "all 0.35s ease";
    card.style.opacity = "0";
    card.style.transform = "scale(0.96)";
  }

  let dashboardLoaded = false;
  let finalized = false;
  let fallbackTimer;
  let fadeTimer;

  function reveal() {
    if (stage) stage.classList.add("revealed");
    if (overlay) overlay.classList.add("cinematic-fade-out");
  }

  function finalize() {
    if (finalized) return;
    finalized = true;

    clearTimeout(fallbackTimer);
    clearTimeout(fadeTimer);

    reveal();

    setTimeout(() => {
      if (overlay) {
        overlay.classList.remove("active");
        overlay.classList.remove("cinematic-fade-out");
        overlay.style.display = "none";
        overlay.setAttribute("aria-hidden", "true");
      }
    }, 400);

    if (stage) stage.style.pointerEvents = "all";

    try {
      window.history.replaceState({}, document.title, "/");
      frame?.contentWindow?.focus();
    } catch (error) {
      console.warn("Transition cleanup:", error);
    }
  }

  function fallback() {
    if (dashboardLoaded) {
      finalize();
    } else {
      window.location.replace("/");
    }
  }

  if (frame) {
    frame.addEventListener("load", () => {
      dashboardLoaded = true;
      stage?.classList.add("loaded");
    }, { once: true });

    frame.src = "/";
  }

  fallbackTimer = setTimeout(fallback, 8000);
  fadeTimer = setTimeout(() => {
    if (dashboardLoaded) reveal();
  }, 1620);

  if (overlay && video) {
    overlay.style.display = "flex";
    overlay.classList.add("active");
    overlay.setAttribute("aria-hidden", "false");

    video.currentTime = 0;
    video.loop = false;

    video.onended = finalize;
    video.onerror = fallback;

    const playPromise = video.play();

    if (playPromise) {
      playPromise.catch(() => fallback());
    }
  } else {
    fallback();
  }
}

// ============================================================
// 9. REMEMBERED EMAIL
// ============================================================

function checkRememberedUser() {
  const remembered = localStorage.getItem("siem_remembered_email");
  const emailInput = document.getElementById("inputEmail");

  if (remembered && emailInput) {
    emailInput.value = remembered;
  }
}

// ============================================================
// 10. MODAL CONTROLS
// ============================================================

function initModals() {
  const modalForgot = document.getElementById("modalForgotPassword");
  const modalContact = document.getElementById("modalContactAdmin");
  const modalGoogle = document.getElementById("modalGoogleSSO");

  function openModal(modal) {
    modal?.classList.add("open");
  }

  function closeModal(modal) {
    modal?.classList.remove("open");
  }

  function showResult(element, message, type = "error") {
    if (!element) return;

    element.className = `alert-box ${type} show`;
    element.textContent = message;
  }

  // Modal opening
  document.getElementById("linkForgotPassword")?.addEventListener("click", e => {
    e.preventDefault();
    openModal(modalForgot);
  });

  document.getElementById("linkContactAdmin")?.addEventListener("click", e => {
    e.preventDefault();
    openModal(modalContact);
  });

  document.getElementById("btnGoogleLogin")?.addEventListener("click", async () => {
    openModal(modalGoogle);

    const badge = document.getElementById("googleConfigBadgeText");
    const description = document.getElementById("googleModalDescription");
    const confirm = document.getElementById("btnConfirmGoogleSSO");

    if (badge) badge.textContent = "Checking Google OAuth configuration...";

    try {
      const data = await apiRequest("/api/auth/oauth/google/url");

      if (data.is_configured && data.auth_url) {
        if (badge) badge.textContent = "OAuth 2.0: Connected";

        if (description) {
          description.textContent = "Google sign-in is configured.";
        }

        if (confirm) {
          confirm.textContent = "Proceed to Google Sign-In";
          confirm.onclick = () => {
            window.location.href = data.auth_url;
          };
        }
      } else {
        if (badge) badge.textContent = "Google OAuth is not configured";

        if (description) {
          description.textContent =
            "Google sign-in is currently unavailable. Use your authorized email and password.";
        }

        if (confirm) confirm.disabled = true;
      }
    } catch (error) {
      if (badge) badge.textContent = error.message;
    }
  });

  // Modal close buttons
  const closeButtons = [
    ["btnCloseForgotModal", modalForgot],
    ["btnCancelForgot", modalForgot],
    ["btnCloseContactModal", modalContact],
    ["btnCancelContact", modalContact],
    ["btnCloseGoogleModal", modalGoogle],
    ["btnCancelGoogle", modalGoogle]
  ];

  closeButtons.forEach(([id, modal]) => {
    document.getElementById(id)?.addEventListener("click", () => {
      closeModal(modal);
    });
  });

  [modalForgot, modalContact, modalGoogle].forEach(modal => {
    modal?.addEventListener("click", e => {
      if (e.target === modal) closeModal(modal);
    });
  });

  // ==========================================================
  // 11. FORGOT PASSWORD
  // ==========================================================

  document.getElementById("btnSubmitForgot")?.addEventListener("click", async () => {
    const email = document.getElementById("inputForgotEmail")?.value.trim();
    const result = document.getElementById("forgotResultBox");
    const button = document.getElementById("btnSubmitForgot");
    const resetStep = document.getElementById("resetPasswordStep");
    const tokenInput = document.getElementById("inputResetToken");

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showResult(result, "Please enter a valid email address.");
      return;
    }

    button.disabled = true;

    try {
      const data = await apiRequest("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email })
      });

      showResult(
        result,
        data.message || "Password recovery request submitted.",
        "success"
      );

      if (resetStep && data.recovery_token) {
        resetStep.style.display = "block";
        if (tokenInput) tokenInput.value = data.recovery_token;
      }

      button.textContent = "Request Submitted";

    } catch (error) {
      showResult(result, error.message);
      button.disabled = false;
    }
  });

  // ==========================================================
  // 12. RESET PASSWORD
  // ==========================================================

  document.getElementById("btnApplyNewPassword")?.addEventListener("click", async () => {
    const token = document.getElementById("inputResetToken")?.value.trim();
    const password = document.getElementById("inputNewPassword")?.value;
    const result = document.getElementById("forgotResultBox");
    const button = document.getElementById("btnApplyNewPassword");

    if (!token) {
      showResult(result, "Please enter the recovery token.");
      return;
    }

    if (!password || password.length < 8) {
      showResult(result, "Password must contain at least 8 characters.");
      return;
    }

    button.disabled = true;

    try {
      const data = await apiRequest("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({
          token,
          new_password: password
        })
      });

      showResult(
        result,
        data.message || "Password updated successfully.",
        "success"
      );

      const loginEmail = document.getElementById("inputEmail");
      const loginPassword = document.getElementById("inputPassword");

      if (loginEmail && data.email) loginEmail.value = data.email;
      if (loginPassword) loginPassword.value = "";

      setTimeout(() => {
        closeModal(modalForgot);
        showAlert("Password reset successful. Please log in.", "success");
      }, 1200);

    } catch (error) {
      showResult(result, error.message);
      button.disabled = false;
    }
  });

  // ==========================================================
  // 13. CONTACT ADMINISTRATOR
  // ==========================================================

  document.getElementById("btnSubmitContact")?.addEventListener("click", async () => {
    const name = document.getElementById("inputContactName")?.value.trim();
    const email = document.getElementById("inputContactEmail")?.value.trim();
    const clearance = document.getElementById("selectClearance")?.value;
    const reason = document.getElementById("inputContactReason")?.value.trim();

    const result = document.getElementById("contactResultBox");
    const button = document.getElementById("btnSubmitContact");

    if (!name || name.length < 2) {
      showResult(result, "Please enter your full name.");
      return;
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showResult(result, "Please enter a valid email address.");
      return;
    }

    if (!reason || reason.length < 10) {
      showResult(result, "Please provide a reason of at least 10 characters.");
      return;
    }

    button.disabled = true;

    try {
      const data = await apiRequest("/api/auth/contact-admin", {
        method: "POST",
        body: JSON.stringify({
          name,
          email,
          clearance_level: clearance,
          reason
        })
      });

      showResult(
        result,
        data.ticket_id
          ? `Access request submitted. Ticket ID: ${data.ticket_id}`
          : data.message || "Request submitted successfully.",
        "success"
      );

      button.textContent = "Submitted";

    } catch (error) {
      showResult(result, error.message);
      button.disabled = false;
    }
  });

  // ==========================================================
  // 14. GOOGLE SSO CONFIRMATION
  // ==========================================================

  document.getElementById("btnConfirmGoogleSSO")?.addEventListener("click", async () => {
    const result = document.getElementById("googleResultBox");
    const button = document.getElementById("btnConfirmGoogleSSO");

    if (button.disabled) return;

    button.disabled = true;

    try {
      const data = await apiRequest("/api/auth/google", {
        method: "POST",
        body: JSON.stringify({
          requested_email: "analyst.google@soc-siem.cloud"
        })
      });

      if (!data.session_token) {
        throw new Error("Backend did not return a session token.");
      }

      sessionStorage.setItem("siem_auth_token", data.session_token);
      sessionStorage.setItem(
        "siem_operator",
        JSON.stringify(data.user || {})
      );

      showResult(
        result,
        data.message || "Google authentication successful.",
        "success"
      );

      setTimeout(() => {
        closeModal(modalGoogle);
        playSuccessTransitionAndRedirect();
      }, 700);

    } catch (error) {
      showResult(result, error.message);
      button.disabled = false;
    }
  });
}