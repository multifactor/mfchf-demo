import hotp from './hotp';

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

      if (user === null) {
        // const target = await random(0, (10 ** 6) - 1)
        const hotpSecret = new Uint8Array(24);
        crypto.getRandomValues(hotpSecret);
        const recoveryCode = crypto.randomUUID();
        const firstCode = await hotp(hotpSecret, 1);

        // const offset = mod(target - code, 10 ** 6)
        // const uri = speakeasy.otpauthURL({ secret: secret.toString('hex'), encoding: 'hex', label: 'mfchf', type: 'hotp', counter: 1, issuer: 'mfchf', algorithm: 'sha1', digits: 6 })
        // const salt = await crypto.randomBytes(24)
        // const hash = await argon2.hash({ pass: password + target, salt, time: 100, mem: 4096, type: argon2.ArgonType.Argon2id })
        // const pad = xor(hash.hash, secret)
        // const sha = crypto.createHash('sha256').update(hash.hash).digest('base64')
        // const out = 'mfchf-argon2id-hotp6#1,' + offset + ',' + pad.toString('base64') + '#' + sha + '#' + salt.toString('base64')
        // console.log(out)
        // return { uri, out }

        await env.DB.put(key, JSON.stringify({
          email, password, recoveryCode, hotpSecret
        }));
        return new Response(JSON.stringify({
          email, hotpSecret: buf2hex(hotpSecret), recoveryCode, firstCode
        }), {status: 200});
      } else {
        return new Response("User already exists", {status: 400});
      }
    }
  } catch (err) {
    return new Response("Internal error: " + err.name + ": " + err.message, {status: 500});
  }
}
