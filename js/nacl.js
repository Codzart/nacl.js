NaCl = function (secretkey) {

    this.crypto_secretbox_KEYBYTES = 32;
    this.crypto_secretbox_NONCEBYTES = 24;
    this.crypto_secretbox_ZEROBYTES = 32;
    this.crypto_secretbox_BOXZEROBYTES = 16;
    this.crypto_secretbox_BEFORENMBYTES = 32;
    
    this.privatekey = new Array(this.crypto_secretbox_KEYBYTES);
    this.publickey = new Array(this.crypto_secretbox_KEYBYTES);
    this.precomputed = new Array(this.crypto_secretbox_BEFORENMBYTES);

    // methods
    this.encrypt = function (input, nonce) {
        var paddedinput = new Array(input.length + this.crypto_secretbox_ZEROBYTES);
        zeroFill(paddedinput);
        var output = new Array(input.length + this.crypto_secretbox_ZEROBYTES);
        zeroFill(output);

        arraycopy(input, 0, paddedinput, this.crypto_secretbox_ZEROBYTES, input.length);
        curve25519xsalsa20poly1305.crypto_box(output, paddedinput, paddedinput.length, nonce, this.publickey, this.privatekey);

        return output;
    };

    this.decrypt = function (input, nonce) {
        var paddedoutput = new Array(input.length);
        var output = new Array(input.length - this.crypto_secretbox_ZEROBYTES);

        curve25519xsalsa20poly1305.crypto_box(paddedoutput, input, input.length, nonce, this.publickey, this.privatekey);
        arraycopy(paddedoutput, this.crypto_secretbox_ZEROBYTES, output, 0, paddedoutput.length - this.crypto_secretbox_ZEROBYTES);

        return output;
    }

    this.getBinary = function (s) {
        var len = s.length;
        var data = new Array(len / 2);

        for (var i = 0; i < len; i += 2) {
            data[i / 2] = toByte((parseInt(s.charAt(i), 16) << 4) + parseInt(s.charAt(i + 1), 16));
        }

        return data;
    }
    
    // try different (CS)PRNG here as needed
    this.prngBytes = function(n) {    	    
    	var rBytes = new Array(n || 0);
      
    	for (var i=0; i<rBytes.length; i++) {
        // from http://www.ecma-international.org/publications/standards/Ecma-262-arch.htm
        // "Math.random() returns a number value with positive sign, greater than or equal to 0 but less than 1, 
        // chosen randomly or pseudo randomly with approximately uniform distribution over that range, using an 
        // implementation-dependent algorithm or strategy. This function takes no arguments."
    		rBytes[i] = Math.floor(256*Math.random());
        //rBytes[i] = Math.floor(256*
        //            ('function' == typeof LFib)                 ? LFib() :
        //            ('function' == typeof LFib)                 ? LFib() :
        //            ('function' == typeof LFib)                 ? LFib() :
        //            ('function' == typeof LFib)                 ? LFib() :
        //            ('function' == typeof window.crypto.random) ? window.crypto.random() : 
        //                                                          Math.random()
        //            );            		        
    	}
    	return rBytes;
    }

    // constructor
// IMHO(Codzart): secretkey should be accepted as follows:
//    if  secretkey is byte array 
//          of size 0 then set as byte array of size (crypto_secretbox_KEYBYTES) containing random bytes
//          of size (crypto_secretbox_KEYBYTES) then proceed
//          else throw("secretkey byte array wrong size")
//    else if secretkey is string 
//          of size 0 then set as byte array of size (crypto_secretbox_KEYBYTES) containing random bytes
//          of size (crypto_secretbox_KEYBYTES * 2) then convert to byte array of size (crypto_secretbox_KEYBYTES)
//          else throw("secretkey string wrong size")
//    else if secretkey is null then set as byte array of size (crypto_secretbox_KEYBYTES) containing random bytes
//        else throw("secretkey invalid input")
//
    if (typeof secretkey === "object") {
        if (secretkey.length == 0) {
            this.privatekey = this.prngBytes(this.crypto_secretbox_KEYBYTES);
        } else if (secretkey.length != (this.crypto_secretbox_KEYBYTES)) {
            throw "secretkey byte array wrong size";
        } else {
            // there is a latent bug here if secretkey.length = 32, but without elements.
            this.privatekey = secretkey;
        }
    } else if (typeof secretkey === "string") {
        if (secretkey.length == 0) {
            this.privatekey = this.prngBytes(this.crypto_secretbox_KEYBYTES);
        } else if (secretkey.length != (this.crypto_secretbox_KEYBYTES * 2)) {
            throw "secretkey string wrong size";
        } else {
            this.privatekey = this.getBinary(secretkey);
        }
    } else if (typeof secretkey === "null") {
        this.privatekey = this.prngBytes(this.crypto_secretbox_KEYBYTES);
    } else throw ("secretkey invalid input");

    // this.publickey should only be derived from this.privatekey
    curve25519xsalsa20poly1305.crypto_box_getpublickey(this.publickey, this.privatekey);

};

// for filling new arrays with zero
function zeroFill(array) {
    for (var i = 0; i < array.length; i++) {
        array[i] = 0;
    }
}

// clone of Java's System.arraycopy
function arraycopy(src, srcpos, dest, destpos, length) {
    var j = 0;

    for (var i = 0; i < length; i++) {
        //var v = src[srcpos + i]; 
        dest[destpos + j] = src[srcpos + i];
        j++;
    }
}

// clone of Java's String.getBytes
// source: http://stackoverflow.com/questions/1240408/reading-bytes-from-a-javascript-string
function stringToBytes(str) {
    var ch, st, re = [],
        j = 0;

    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i);

        if (ch < 127) {
            re[j++] = ch & 0xFF;
        } else {
            st = []; // clear stack
            do {
                st.push(ch & 0xFF); // push byte to stack
                ch = ch >> 8; // shift value down by 1 byte
            }
            while (ch);

            // add stack contents to result
            // done because chars have "wrong" endianness
            st = st.reverse();
            for (var k = 0; k < st.length; ++k) {
                re[j++] = st[k];
            }
        }
    }
    // return an array of bytes
    return re;
}

// clone of Java's String(byte[]) constructor
// source: http://stackoverflow.com/questions/3195865/javascript-html-converting-byte-array-to-string
function bytesToString(bytes) {
    return String.fromCharCode.apply(String, bytes);
}

// near clone of Java's casting of integers to bytes
// warning: doesn't handle negative integers properly
function toByte(i) {
    return ((i + 128) % 256) - 128;
}

function bytesToHex(bytes) {
				var hexDigits = "0123456789ABCDEF";
				var str = "";
				
				for (var i = 0; i < bytes.length; i ++) {
					var byte = bytes[i];
					str += hexDigits[(byte & 0xF0) >> 4] + hexDigits[byte & 0x0F] + "  ";
				}
				
				return str;
}