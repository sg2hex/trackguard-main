const isValidEmail = (email) => {
  if (typeof email !== 'string' || email.length > 254 || /\s/.test(email)) {
    return false;
  }

  const atIndex = email.indexOf('@');
  if (atIndex <= 0 || atIndex !== email.lastIndexOf('@')) {
    return false;
  }

  const localPart = email.slice(0, atIndex);
  const domain = email.slice(atIndex + 1);
  if (localPart.length > 64 || localPart.startsWith('.') || localPart.endsWith('.')
    || localPart.includes('..')
    || !/^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(localPart)) {
    return false;
  }

  const labels = domain.split('.');
  return domain.length <= 253
    && labels.length >= 2
    && labels.every((label) => label.length > 0 && label.length <= 63
      && /^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?$/i.test(label))
    && labels[labels.length - 1].length >= 2;
};

const getPasswordError = (password) => {
  if (typeof password !== 'string' || password.length < 6 || password.length > 12) {
    return 'Password must be 6-12 characters long.';
  }
  if (!/[0-9]/.test(password) || !/[a-z]/.test(password)
    || !/[A-Z]/.test(password) || !/[^A-Za-z0-9\s]/.test(password)
    || /\s/.test(password)) {
    return 'Password must include a number, an uppercase letter, a lowercase letter, and a special character, with no spaces.';
  }
  return null;
};

module.exports = { isValidEmail, getPasswordError };
