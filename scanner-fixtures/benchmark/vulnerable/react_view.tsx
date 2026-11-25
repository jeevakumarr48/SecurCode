import React from "react";

export function Preview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />; // expect: JSSEC007
}

export function Next() {
  window.location.href = new URLSearchParams(window.location.search).get("next") ?? "/"; // expect: JSSEC012
  return null;
}
