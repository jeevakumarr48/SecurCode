function evaluateRequest() {
  eval(request.body.source);
}

function handleRequest() {
  evaluateRequest();
}

handleRequest();
