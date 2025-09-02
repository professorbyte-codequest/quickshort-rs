(function () {
  const b64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  async function sha256(str) {
    const enc = new TextEncoder();
    const data = enc.encode(str);
    return await crypto.subtle.digest("SHA-256", data);
  }

  async function pkceStart() {
    const codeVerifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const codeChallenge = b64url(await sha256(codeVerifier));
    const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
    sessionStorage.setItem("qs_pkce_verifier", codeVerifier);
    sessionStorage.setItem("qs_oauth_state", state);
    return { codeVerifier, codeChallenge, state };
  }

  function cfg() {
    if (!window.QS_AUTH_CONFIG) throw new Error("QS_AUTH_CONFIG missing");
    return window.QS_AUTH_CONFIG;
  }

  // Build authorize URL (Cognito Hosted UI)
  async function buildAuthorizeUrl() {
    const c = cfg();
    const { codeChallenge, state } = await pkceStart();
    const params = new URLSearchParams({
      client_id: c.clientId,
      response_type: "code",
      redirect_uri: c.redirectUri,
      scope: c.scope,
      code_challenge_method: "S256",
      code_challenge: codeChallenge,
      state,
      identity_provider: c.identityProvider, // Google only for now
    });
    return `${c.cognitoDomain}/oauth2/authorize?${params.toString()}`;
  }

  // Exchange code -> tokens
  async function exchangeCode(code) {
    const c = cfg();
    const codeVerifier = sessionStorage.getItem("qs_pkce_verifier");
    if (!codeVerifier) throw new Error("Missing PKCE verifier");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: c.clientId,
      code,
      redirect_uri: c.redirectUri,
      code_verifier: codeVerifier,
    });
    const resp = await fetch(`${c.cognitoDomain}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!resp.ok) {
      const t = await resp.text();
      throw new Error(`Token exchange failed: ${resp.status} ${t}`);
    }
    const tok = await resp.json();
    // Persist; ID token is what your API authorizer expects
    sessionStorage.removeItem("qs_pkce_verifier");
    localStorage.setItem("qs_id_token", tok.id_token || "");
    localStorage.setItem("qs_access_token", tok.access_token || "");
    localStorage.setItem("qs_refresh_token", tok.refresh_token || "");
    return tok;
  }

  // Small helper to call our API with the ID token
  async function qsApi(path, init = {}) {
    const idt = localStorage.getItem("qs_id_token");
    const headers = new Headers(init.headers || {});
    if (idt) headers.set("Authorization", `Bearer ${idt}`);
    return fetch(path, { ...init, headers });
  }

  window.QSAuth = { buildAuthorizeUrl, exchangeCode, qsApi };
})();
