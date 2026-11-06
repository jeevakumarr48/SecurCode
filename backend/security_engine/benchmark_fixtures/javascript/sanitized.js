const safeHtml = DOMPurify.sanitize(request.body.html);
target.innerHTML = safeHtml;
