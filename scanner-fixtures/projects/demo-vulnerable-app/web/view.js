export function renderGreeting(name) {
  document.getElementById("greeting").innerHTML = name;
}

export function makeResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}
