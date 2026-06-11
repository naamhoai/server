const GMAIL_REGEX = /^[^\s@]+@gmail\.com$/i;
const VN_PHONE_REGEX = /^0[39]\d{8}$/;
const MIN_PASSWORD_LEN = 6;
const MAX_PASSWORD_LEN = 30;

export function validatePhoneOrEmail(value) {
  const v = (value || '').trim();
  if (!v) {
    return { ok: false, message: 'Please enter a phone number or Gmail address.' };
  }

  if (v.includes('@')) {
    if (!GMAIL_REGEX.test(v)) {
      return {
        ok: false,
        message: 'Only Gmail addresses ending with @gmail.com are allowed.',
      };
    }
    return { ok: true };
  }

  if (!/^\d+$/.test(v)) {
    return {
      ok: false,
      message: 'Phone number must contain digits only (no spaces or symbols).',
    };
  }

  if (!VN_PHONE_REGEX.test(v)) {
    return {
      ok: false,
      message:
        'Phone number must be exactly 10 digits and follow Vietnam mobile format (0, then 3 or 9, then 8 digits).',
    };
  }

  return { ok: true };
}

export function validateEmail(value) {
  const v = (value || '').trim();
  if (!v) {
    return { ok: false, message: 'Please enter your email address.' };
  }
  if (!GMAIL_REGEX.test(v)) {
    return { ok: false, message: 'Only Gmail addresses ending with @gmail.com are allowed.' };
  }
  return { ok: true };
}

export function validateLoginIdentifier(value) {
  const v = (value || '').trim();
  if (!v) {
    return { ok: false, message: 'Please enter your username, phone number, or email.' };
  }

  if (v.includes('@')) {
    const genericEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!genericEmailRegex.test(v)) {
      return { ok: false, message: 'Please enter a valid email address.' };
    }
    return { ok: true };
  }

  if (/^\d+$/.test(v)) {
    if (!VN_PHONE_REGEX.test(v)) {
      return {
        ok: false,
        message: 'Phone number must be a 10-digit Vietnam mobile number starting with 03 or 09.',
      };
    }
    return { ok: true };
  }

  return { ok: true };
}

/**
 * Modern strong password: 6–30 chars, at least one letter and one digit.
 * @param {string} password
 * @returns {{ ok: true } | { ok: false, message: string }}
 */
export function validateStrongPassword(password = '') {
  const p = password;

  if (/[^\x20-\x7E]/.test(p)) {
    return {
      ok: false,
      message: 'Password cannot contain accented or non-standard characters.',
    };
  }

  if (p.length < MIN_PASSWORD_LEN) {
    return {
      ok: false,
      message: `Password must be at least ${MIN_PASSWORD_LEN} characters.`,
    };
  }
  if (p.length > MAX_PASSWORD_LEN) {
    return {
      ok: false,
      message: `Password must be at most ${MAX_PASSWORD_LEN} characters.`,
    };
  }
  if (!/[a-zA-Z]/.test(p)) {
    return {
      ok: false,
      message: 'Password must contain at least one letter.',
    };
  }
  if (!/\d/.test(p)) {
    return { ok: false, message: 'Password must contain at least one number.' };
  }
  
  return { ok: true };
}
