let formatCounter = (counter) => {
  let binStr = ('0'.repeat(64) + counter.toString(2)).slice(-64);
  let intArr = [];

  for (let i = 0; i < 8; i++) {
    intArr[i] = parseInt(binStr.slice(i * 8, i * 8 + 8), 2);
  }

  return Uint8Array.from(intArr).buffer;
};

let truncate = (buffer) => {
  let offset = buffer[buffer.length - 1] & 0xf;
  return (
    ((buffer[offset] & 0x7f) << 24) |
    ((buffer[offset + 1] & 0xff) << 16) |
    ((buffer[offset + 2] & 0xff) << 8) |
    (buffer[offset + 3] & 0xff)
  );
};

export default async function hotp(secret, counter) {
  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: {name: 'SHA-1'} },
    false,
    ['sign']
  )
  const hmac = crypto.subtle.sign('HMAC', key, formatCounter(counter))
  return ('000000' + (truncate(new Uint8Array(hmac)) % 10 ** 6 )).slice(-6)
}
