const crypto = require("crypto");
const fs = require("fs");
const vm = require("vm");
const { unserialize } = require("node-serialize");

function render(message) {
  document.getElementById("out").innerHTML = message; // expect: JSSEC006
  panel.insertAdjacentHTML("beforeend", message); // expect: JSSEC006
  document.write(userContent); // expect: JSSEC006
  setTimeout("refresh()", 1000); // expect: JSSEC008
}

const hash = crypto.createHash("md5").update(data).digest("hex"); // expect: JSSEC009
const cipher = crypto.createCipheriv("aes-128-ecb", key, null); // expect: JSSEC009
const resetToken = Math.random().toString(36).slice(2); // expect: JSSEC010
const agent = new https.Agent({ rejectUnauthorized: false }); // expect: JSSEC011
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // expect: JSSEC011

app.get("/go", (req, res) => {
  res.redirect(req.query.next); // expect: JSSEC012
});

app.get("/user", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`); // expect: JSSEC013
  const other = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'"); // expect: JSSEC013
  const profile = unserialize(req.cookies.profile); // expect: JSSEC014
  fs.readFile(req.query.file, "utf8", () => {}); // expect: JSSEC015
  console.log("user password", user.password); // expect: JSSEC016
  const upstream = await fetch(req.query.url); // expect: JSSEC017
  vm.runInNewContext(req.body.expression, {}); // expect: JSSEC019
});

const GITHUB = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"; // expect: JSSEC018
