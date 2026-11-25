const crypto = require("crypto");

function render(message) {
  document.getElementById("out").textContent = message;
  document.getElementById("static").innerHTML = "<strong>Ready</strong>";
  panel.insertAdjacentHTML("beforeend", "<li>static</li>");
  setTimeout(() => refresh(), 1000);
}

// document.write(userContent) in a comment is ignored
const note = "element.innerHTML = value is only text here";
const hash = crypto.createHash("sha256").update(data).digest("hex");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const resetToken = crypto.randomBytes(32).toString("hex");
const jitter = Math.random() * 100;
const agent = new https.Agent({ rejectUnauthorized: true });

app.get("/user", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
  const template = await db.query(`SELECT * FROM users WHERE active = true`);
  console.log("login for", user.email);
  res.redirect("/dashboard");
});
