const toggleButton = document.querySelector("[data-toggle-password]");

if (toggleButton) {
  toggleButton.addEventListener("click", () => {
    const input = document.querySelector("#password");
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleButton.textContent = isPassword ? "Masquer" : "Voir";
  });
}

const chatForm = document.querySelector("[data-chat-form]");
const chatFeed = document.querySelector("[data-chat-feed]");
const requestForm = document.querySelector("[data-request-form]");
const crmForm = document.querySelector("[data-crm-form]");
const appShell = document.querySelector(".app-shell");
const slug = appShell?.dataset.slug;
const stayMenu = document.querySelector(".stay-menu");
const languageChoices = document.querySelectorAll("[data-lang-choice]");

if (stayMenu) {
  const mobileMenu = window.matchMedia("(max-width: 760px)");
  const syncMenuState = () => {
    stayMenu.open = !mobileMenu.matches;
  };
  syncMenuState();
  if (mobileMenu.addEventListener) {
    mobileMenu.addEventListener("change", syncMenuState);
  } else if (mobileMenu.addListener) {
    mobileMenu.addListener(syncMenuState);
  }
}

languageChoices.forEach((choice) => {
  choice.addEventListener("click", () => {
    localStorage.setItem("liberty_lang", choice.dataset.langChoice);
    document.cookie = `liberty_lang=${encodeURIComponent(choice.dataset.langChoice)}; Path=/; Max-Age=31536000; SameSite=Lax`;
  });
});

const cookieBanner = document.querySelector("[data-cookie-banner]");
const cookieAccept = document.querySelector("[data-cookie-accept]");

if (cookieBanner && !localStorage.getItem("liberty_cookie_notice")) {
  cookieBanner.hidden = false;
}

if (cookieAccept) {
  cookieAccept.addEventListener("click", () => {
    localStorage.setItem("liberty_cookie_notice", "accepted");
    cookieBanner.hidden = true;
  });
}

async function track(event, value = "") {
  if (!slug) return;
  try {
    await fetch(`/api/analytics/${slug}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, value }),
    });
  } catch {
    // Analytics must never block the traveler experience.
  }
}

function appendMessage(role, text) {
  const message = document.createElement("div");
  message.className = `chat-message ${role}`;
  message.textContent = text;
  chatFeed.appendChild(message);
  chatFeed.scrollTop = chatFeed.scrollHeight;
  return message;
}

if (chatForm && chatFeed) {
  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = chatForm.elements.message;
    const text = input.value.trim();
    if (!text) return;

    appendMessage("user", text);
    input.value = "";
    const pending = appendMessage("assistant", "Je consulte les informations Liberty du logement...");

    try {
      const response = await fetch(`/api/chat/${slug}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      const result = await response.json();
      pending.textContent = result.answer || result.error || "Réponse indisponible. Le Centre de Services Liberty reste disponible.";
    } catch {
      pending.textContent = "L'assistant est momentanément indisponible. Vous pouvez créer une demande dans le Centre de Services Liberty.";
    }
  });
}

if (requestForm) {
  requestForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = requestForm.querySelector("[data-request-status]");
    const payload = Object.fromEntries(new FormData(requestForm));
    status.textContent = "Envoi en cours...";

    try {
      const response = await fetch(`/api/service-request/${slug}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      status.textContent = result.message || result.error || "Demande enregistrée.";
      if (result.ok) requestForm.reset();
    } catch {
      status.textContent = "Impossible d'envoyer la demande pour le moment.";
    }
  });
}

if (crmForm) {
  crmForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = crmForm.querySelector("[data-crm-status]");
    const data = Object.fromEntries(new FormData(crmForm));
    data.marketingConsent = crmForm.elements.marketingConsent.checked;
    status.textContent = "Enregistrement en cours...";

    try {
      const response = await fetch(`/api/crm/${slug}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const result = await response.json();
      status.textContent = result.message || result.error || "Informations enregistrées.";
      if (result.ok) crmForm.reset();
    } catch {
      status.textContent = "Impossible d'enregistrer ces informations pour le moment.";
    }
  });
}

document.querySelectorAll("[data-service]").forEach((button) => {
  button.addEventListener("click", () => {
    const form = document.querySelector("[data-request-form]");
    if (!form) return;
    form.scrollIntoView({ behavior: "smooth", block: "start" });
    form.elements.type.value = "Réserver une option payante";
    form.elements.message.value = `Je souhaite demander : ${button.dataset.service}`;
  });
});

document.querySelectorAll("[data-track]").forEach((element) => {
  element.addEventListener("click", () => {
    track(element.dataset.track, element.dataset.trackValue || element.textContent.trim());
  });
});

const wifiPanel = document.querySelector("[data-wifi-panel]");
if (wifiPanel && "IntersectionObserver" in window) {
  let tracked = false;
  const observer = new IntersectionObserver((entries) => {
    if (!tracked && entries.some((entry) => entry.isIntersecting)) {
      tracked = true;
      track("wifi_view", "display");
      observer.disconnect();
    }
  }, { threshold: 0.5 });
  observer.observe(wifiPanel);
}
