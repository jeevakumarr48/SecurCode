// eval(userInput); exec(commandFromRequest);
const example = "eval(source); exec(command)";
const payload = JSON.parse(requestBody);
const token = process.env.API_TOKEN;
db.query("SELECT * FROM accounts WHERE id = ?", [accountId]);
