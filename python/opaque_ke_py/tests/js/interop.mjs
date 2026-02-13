function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
  });
}

function respond(payload) {
  process.stdout.write(JSON.stringify(payload));
}

const input = await readStdin();
let payload = null;
try {
  payload = input ? JSON.parse(input) : null;
} catch (err) {
  respond({ ok: false, error: "invalid_json", detail: String(err) });
  process.exit(1);
}

if (!payload || !payload.action) {
  respond({ ok: false, error: "missing_action" });
  process.exit(1);
}

let opaque = null;
try {
  const mod = await import("@serenity-kit/opaque");
  opaque = mod.default ?? mod;
  if (opaque?.ready) {
    await opaque.ready;
  }
} catch (err) {
  respond({ ok: false, error: "missing_dependency", detail: String(err) });
  process.exit(1);
}

const args = payload.args ?? {};

function maybeAssign(target, key, value) {
  if (value !== undefined && value !== null) {
    target[key] = value;
  }
}

try {
  let result = null;
  switch (payload.action) {
    case "createServerSetup": {
      const serverSetup = opaque.server.createSetup();
      const serverStaticPublicKey = opaque.server.getPublicKey(serverSetup);
      result = { serverSetup, serverStaticPublicKey };
      break;
    }
    case "clientStartRegistration": {
      const params = { password: args.password };
      maybeAssign(params, "keyStretching", args.keyStretching);
      result = opaque.client.startRegistration(params);
      break;
    }
    case "serverCreateRegistrationResponse": {
      const params = {
        serverSetup: args.serverSetup,
        userIdentifier: args.userIdentifier,
        registrationRequest: args.registrationRequest,
      };
      result = opaque.server.createRegistrationResponse(params);
      break;
    }
    case "clientFinishRegistration": {
      const params = {
        clientRegistrationState: args.clientRegistrationState,
        registrationResponse: args.registrationResponse,
        password: args.password,
      };
      maybeAssign(params, "identifiers", args.identifiers);
      result = opaque.client.finishRegistration(params);
      break;
    }
    case "clientStartLogin": {
      const params = { password: args.password };
      maybeAssign(params, "keyStretching", args.keyStretching);
      result = opaque.client.startLogin(params);
      break;
    }
    case "serverStartLogin": {
      const params = {
        userIdentifier: args.userIdentifier,
        registrationRecord: args.registrationRecord,
        serverSetup: args.serverSetup,
        startLoginRequest: args.startLoginRequest,
      };
      maybeAssign(params, "identifiers", args.identifiers);
      maybeAssign(params, "context", args.context);
      result = opaque.server.startLogin(params);
      break;
    }
    case "clientFinishLogin": {
      const params = {
        clientLoginState: args.clientLoginState,
        loginResponse: args.loginResponse,
        password: args.password,
      };
      maybeAssign(params, "identifiers", args.identifiers);
      maybeAssign(params, "context", args.context);
      result = opaque.client.finishLogin(params);
      if (!result) {
        respond({ ok: false, error: "login_failed" });
        process.exit(1);
      }
      break;
    }
    case "serverFinishLogin": {
      const params = {
        finishLoginRequest: args.finishLoginRequest,
        serverLoginState: args.serverLoginState,
      };
      maybeAssign(params, "context", args.context);
      result = opaque.server.finishLogin(params);
      break;
    }
    default: {
      respond({ ok: false, error: "unknown_action", detail: payload.action });
      process.exit(1);
    }
  }

  respond({ ok: true, result });
} catch (err) {
  respond({ ok: false, error: "exception", detail: String(err) });
  process.exit(1);
}
