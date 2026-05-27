// Small landing-page typewriter effect to make the prototype feel less static.
document.addEventListener("DOMContentLoaded", function () {
  const introText = "Welcome to Vigil.AI — The Intelligent Traffic Analyzer.";
  const introElement = document.getElementById("intro-text");
  let i = 0;

  function typeWriter() {
    if (i < introText.length) {
      introElement.textContent += introText.charAt(i);
      i++;
      setTimeout(typeWriter, 50);
    }
  }

  typeWriter();
});

// Sends a raw 32-feature vector to the Python model through the Node backend.
async function sendToModel(features) {
  console.log("📤 Sending to model:", features);

  const response = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features: features })
  });

  const data = await response.json();
  console.log("📥 Model Raw Response:", data);

  return data.prediction;
}
// Chatbot behavior for the main Vigil AI page.

document.addEventListener("DOMContentLoaded", function () {
  const chatbotContainer = document.getElementById("chatbot-container");
  const closeBtn = document.getElementById("close-btn");
  const sendBtn = document.getElementById("send-btn");
  const chatbotInput = document.getElementById("chatbot-input");
  const chatbotMessages = document.getElementById("chatbot-messages");
  const chatbotIcon = document.getElementById("chatbot-icon");

  closeBtn.addEventListener("click", function () {
    chatbotContainer.classList.add("hidden");
    chatbotIcon.style.display = "flex";
  });

  sendBtn.addEventListener("click", sendMessage);
  chatbotInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") sendMessage();
  });

  function sendMessage() {
    const userMessage = chatbotInput.value.trim();
    if (userMessage) {
      appendMessage("user", userMessage);
      chatbotInput.value = "";
      handleBotLogic(userMessage);
    }
  }

  // Bot responses are typed out so long Gemini answers do not pop in abruptly.
  function typeWriterEffect(element, text, speed = 30) {
    let i = 0;
    function typing() {
      if (i < text.length) {
        element.textContent += text.charAt(i);
        i++;
        setTimeout(typing, speed);
      }
    }
    typing();
  }

  function appendMessage(sender, message) {
    const msg = document.createElement("div");
    msg.classList.add("message", sender);
    msg.textContent = message;
    chatbotMessages.appendChild(msg);
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
  }

  // "analyze ..." is reserved for local model testing; everything else goes to
  // the assistant route so the page can act like both a demo and a chatbot.
  async function handleBotLogic(userMessage) {
    if (userMessage.toLowerCase().startsWith("analyze")) {
      appendMessage("bot", "Analyzing traffic...");

      // The quick demo syntax expects comma-separated numbers after "analyze".
      const values = userMessage
        .replace("analyze", "")
        .trim()
        .split(",")
        .map(Number);

      const prediction = await sendToModel(values);

      const label = interpretPrediction(prediction);

      const botMsg = `🧠 **Traffic Classification:** ${label}`;
      appendMessage("bot", botMsg);
      return;
    }

    await getBotResponse(userMessage);
  }

  // Convert the model's class id into the labels used in the presentation.
  function interpretPrediction(id) {
  const labels = {
    0: "Benign (Normal Traffic)",
    1: "DDoS Attack",
    2: "DoS Attack",
    3: "Port Scan Activity",
    4: "Botnet / Malware Behavior",
    5: "Infiltration Attempt",
    6: "Web Attack Detected"
  };

  return labels[id] || `Unknown Class (${id})`;
}

  async function getBotResponse(userMessage) {
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userMessage }),
      });

      if (!response.ok) {
        appendMessage("bot", "Sorry, there was a server error. Try again.");
        return;
      }

      const data = await response.json();
      console.log("Gemini response:", data);
      const botMessage =
         JSON.stringify(data) || "Sorry, I didn’t get that."; 
        

      const messageElement = document.createElement("div");
      messageElement.classList.add("message", "bot");
      chatbotMessages.appendChild(messageElement);
      typeWriterEffect(messageElement, botMessage, 20);
      chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    } catch (error) {
      console.error("Error fetching bot response:", error);
      appendMessage("bot", "Sorry, something went wrong. Please try again.");
    }
  }
});
