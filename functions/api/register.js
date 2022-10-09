import hotp from './hotp';
const xor = require('buffer-xor');

const validateEmail = (email) => {
  return email.match(
    /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
  );
};

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

function mod (n, m) {
  return ((n % m) + m) % m
}

const sha256 = async (data) => {
  return await crypto.subtle.digest("SHA-256", data);
}

const pbkdf2 = async (pass, salt) => {
  const data = new TextEncoder().encode(pass);
  const key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  const params = { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 1e5 }
  return new Uint8Array(await crypto.subtle.deriveBits(params, key, 256))
}

export async function onRequest(context) {
  try {
    const { request, env } = context;
    const { searchParams } = new URL(request.url);
    const email = searchParams.get('email').trim().toLowerCase();
    const password = searchParams.get('password').trim();

    if (request.method !== "POST") {
      return new Response("Expected POST", {status: 400});
    } else if (typeof email !== 'string' || email.length === 0) {
      return new Response("Expected email", {status: 400});
    } else if (!validateEmail(email)) {
      return new Response("Invalid email", {status: 400});
    } else if (typeof password !== 'string' || password.length === 0) {
      return new Response("Expected password", {status: 400});
    } else {
      const key = 'user#' + email.toLowerCase();
      const user = await env.DB.get(key);

      if (user === null || true) {
        const target = Math.floor(Math.random() * (10 ** 6));
        const hotpSecret = new Uint8Array(24);
        crypto.getRandomValues(hotpSecret);
        const recoveryCode = crypto.randomUUID();
        const nextCode = await hotp(hotpSecret, 2);
        const offset = mod(target - nextCode, 10 ** 6)
        const salt = new Uint8Array(24);
        crypto.getRandomValues(salt);

        const mainHash = await pbkdf2(password + target, salt)
        // const hotpRecoveryHash = await argon2.hash({ pass: password + recoveryCode, salt, time: 50, mem: 1024, type: argon2.ArgonType.Argon2id })
        // const passwordRecoveryHash = await argon2.hash({ pass: recoveryCode + target, salt, time: 50, mem: 1024, type: argon2.ArgonType.Argon2id })
        // const pad = xor(hash.hash, hotpSecret)
        const pad = hotpSecret

        const laterCode = await hotp(hotpSecret, 3);
        const windowOffset = mod(target - laterCode, 10 ** 6)

        await env.DB.put(key, JSON.stringify({
          offset,
          windowOffset,
          salt: buf2hex(salt),
          ctr: 2,
          pad: buf2hex(pad),
          mainHash: buf2hex(sha256(mainHash)),
          // hotpRecoveryHash: buf2hex(hotpRecoveryHash.hash),
          // passwordRecoveryHash: buf2hex(passwordRecoveryHash.hash)
        }));
        return new Response(JSON.stringify({
          email, hotpSecret: buf2hex(hotpSecret), recoveryCode, nextCode
        }), {status: 200});
      } else {
        return new Response("User already exists", {status: 400});
      }
    }
  } catch (err) {
    return new Response("Internal error: " + err.name + ": " + err.message, {status: 400});
  }
}
