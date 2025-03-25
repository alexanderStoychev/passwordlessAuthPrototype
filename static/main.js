document.addEventListener("DOMContentLoaded", () => {
  const registerBtn = document.getElementById("register");
  const loginBtn = document.getElementById("login");
  const status = document.getElementById("status");

  registerBtn.addEventListener("click", async () => {
    status.innerText = "Starting registration...";
    try {
      const resp = await fetch("/register/options", { method: "POST" });
      const options = await resp.json();
      // Convert challenge and user.id from base64 to ArrayBuffer.
      options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
      options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

      const credential = await navigator.credentials.create({ publicKey: options });
      
      const credentialData = {
        id: credential.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
        type: credential.type,
        response: {
          attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
        }
      };
      
      const result = await fetch("/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentialData)
      });
      const text = await result.text();
      status.innerText = text;
    } catch (e) {
      console.error(e);
      status.innerText = "Registration failed: " + e;
    }
  });

  loginBtn.addEventListener("click", async () => {
    status.innerText = "Starting login...";
    try {
      const resp = await fetch("/login/options", { method: "POST" });
      const options = await resp.json();
      // Convert challenge and allowCredentials IDs.
      options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
      options.allowCredentials = options.allowCredentials.map(cred => ({
        ...cred,
        id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
      }));

      const assertion = await navigator.credentials.get({ publicKey: options });
      
      const authData = {
        id: assertion.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
        type: assertion.type,
        response: {
          authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
          signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
          userHandle: assertion.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))) : null
        }
      };
      
      const result = await fetch("/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(authData)
      });
      const text = await result.text();
      status.innerText = text;
    } catch (e) {
      console.error(e);
      status.innerText = "Login failed: " + e;
    }
  });
});
