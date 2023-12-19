const crypto = require('crypto');

class Mfa {
  static mfa_TOTPLength = 6;
  static mfa_secretCodeLength = 16;
  static mfa_secretCodeTime = 30;
  static mfa_decodeSecretCodeValidValues = [6, 4, 3, 1, 0];

  static createSecretCode() {
    const base32LookupTable = Mfa.base32LookupTable();
    const createRandomBytes = Mfa.createRandomBytes();

    if (!createRandomBytes) {
      throw new Error("Nishadil\MFA : Failed to create random bytes");
    }

    const secretCode = Array.from({ length: Mfa.mfa_secretCodeLength }, (_, i) => base32LookupTable[createRandomBytes[i] & 31]).join('');

    return secretCode;
  }

  static getTOTP(secretCode) {
    const mfa_time = Math.floor(Date.now() / 1000 / Mfa.mfa_secretCodeTime);
    const secretCodeDecoded = Mfa.decodeSecretCode(secretCode);

    if (!secretCodeDecoded) {
      return '';
    }

    const binaryTime = Buffer.alloc(8);
    binaryTime.writeUInt32BE(mfa_time, 4);

    const hm = crypto.createHmac('sha1', secretCodeDecoded).update(binaryTime).digest();
    const offset = hm[hm.length - 1] & 0x0F;
    const hashpart = hm.slice(offset, offset + 4);
    const value = hashpart.readUInt32BE() & 0x7FFFFFFF;

    return value.toString().padStart(Mfa.mfa_TOTPLength, '0');
  }

  static getHOTP(secretCode, counter) {
    const secretCodeDecoded = Mfa.decodeSecretCode(secretCode);

    if (!secretCodeDecoded) {
      return '';
    }

    const counterBytes = Buffer.alloc(8);
    counterBytes.writeUInt32BE(counter, 4);

    const hm = crypto.createHmac('sha1', secretCodeDecoded).update(counterBytes).digest();
    const offset = hm[hm.length - 1] & 0x0F;
    const hashpart = hm.slice(offset, offset + 4);
    const value = hashpart.readUInt32BE() & 0x7FFFFFFF;

    return value.toString().padStart(Mfa.mfa_TOTPLength, '0');
  }

  static setSecretCodeLength(secretCodeLength = null) {
    if (secretCodeLength === null || secretCodeLength < 16 || secretCodeLength > 128) {
      secretCodeLength = 16;
    }

    Mfa.mfa_secretCodeLength = secretCodeLength;
  }

  static createRandomBytes() {
    try {
      return crypto.randomBytes(Mfa.mfa_secretCodeLength);
    } catch (error) {
      return null;
    }
  }

  static decodeSecretCode(secretCode = '') {
    if (secretCode === null || secretCode === '') {
      return null;
    }

    const base32LookupTable = Mfa.base32LookupTable();
    const base32LookupTableFlip = Object.fromEntries(base32LookupTable.map((value, index) => [value, index]));

    const subStrCount = (secretCode.match(new RegExp(base32LookupTable[32], 'g')) || []).length;

    if (!Mfa.mfa_decodeSecretCodeValidValues.includes(subStrCount)) {
      return null;
    }

    for (let i = 0; i < 4; ++i) {
      if (subStrCount === Mfa.mfa_decodeSecretCodeValidValues[i] &&
          secretCode.slice(-(Mfa.mfa_decodeSecretCodeValidValues[i])) !== base32LookupTable[32].repeat(Mfa.mfa_decodeSecretCodeValidValues[i])) {
        return null;
      }
    }

    const secretCodeArray = secretCode.replace(/=/g, '').split('');
    let secretCodeDecoded = '';

    for (let i = 0; i < secretCodeArray.length; i += 8) {
      let x = '';

      if (!base32LookupTable.includes(secretCodeArray[i])) {
        return null;
      }

      for (let n = 0; n < 8; ++n) {
        x += secretCodeArray[i + n].toString(2).padStart(5, '0');
      }

      const mfaEightBits = x.match(/.{1,8}/g);
      for (let d = 0; d < mfaEightBits.length; ++d) {
        const y = String.fromCharCode(parseInt(mfaEightBits[d], 2));
        secretCodeDecoded += y || y.charCodeAt(0) === 48 ? y : '';
      }
    }

    return secretCodeDecoded;
  }

  static base32LookupTable() {
    return [
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
      'Y', 'Z', '2', '3', '4', '5', '6', '7',
      '=',
    ];
  }
}

module.exports = Mfa;
