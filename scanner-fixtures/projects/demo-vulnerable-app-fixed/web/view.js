export function renderGreeting(name) {
  document.getElementById("greeting").textContent = name;
}

export function makeResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}
