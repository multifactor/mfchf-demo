export function hotp(key, counter, format) {

    function hotp_hexkeytobytestream(s) {
        // s is the key to be converted in bytes
        var b = new Array();
        var last = s.length;
        for (var i = 0; i < last; i = i + 2) {
            var x = s[i] + s[i + 1];
            x.toUpperCase();
            x = "0x" + x;
            x = parseInt(x);
            b[i] = String.fromCharCode(x);
        }
        var ret = new String();
        ret = b.join('');
        return ret;

    }
    function hotp_movingfactortohex(count) {
        // count is the moving factor in OTP to be converted in bytes
        v = decimaltohex(count, 16);
        var decb = new Array();
        lhex = Crypto.util.hexToBytes(v);
        for (var i = 0; i < lhex.length; i++) {
            decb[i] = String.fromCharCode(lhex[i]);
        }
        var retval = new String();
        retval = decb.join('');
        return retval;
    }

    function decimaltohex(d, padding) {
        // d is the decimal value
        // padding is the padding to apply (O pad)
        var hex = Number(d).toString(16);
        padding = typeof(padding) === "undefined" || padding === null ? padding = 2 : padding;
        while (hex.length < padding) {
            hex = "0" + hex;
        }
        return hex;
    }

    function truncatedvalue(h, p) {
        // h is the hash value
        // p is precision
        offset = h[19] & 0xf;
        v = (h[offset] & 0x7f) << 24 | (h[offset + 1] & 0xff) << 16 | (h[offset + 2] & 0xff) << 8 | (h[offset + 3] & 0xff);
        v = "" + v;
        v = v.substr(v.length - p, p);
        return v;
    }

    var hmacBytes = Crypto.HMAC(Crypto.SHA1, Crypto.charenc.Binary.stringToBytes((hotp_movingfactortohex(counter))), Crypto.charenc.Binary.stringToBytes(hotp_hexkeytobytestream(key)));

    if (format == "hex40") {
        return hmacBytes.substring(0, 10);
    } else if (format == "dec6") {
        return truncatedvalue(Crypto.util.hexToBytes(hmacBytes), 6);
    } else if (format == "dec7") {
        return truncatedvalue(Crypto.util.hexToBytes(hmacBytes), 7);
    } else if (format == "dec8") {
        return truncatedvalue(Crypto.util.hexToBytes(hmacBytes), 8);
    }
    else {
        return "unknown format";
    }

}
