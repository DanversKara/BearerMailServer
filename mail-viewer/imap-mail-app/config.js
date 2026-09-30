require('dotenv').config();

// Preset mail server settings
const PRESETS = {
  gmail: { host: 'imap.gmail.com', port: 993, secure: true },
  gmx: { host: 'imap.gmx.com', port: 993, secure: true },
  outlook: { host: 'outlook.office365.com', port: 993, secure: true },
  qq: { host: 'imap.qq.com', port: 993, secure: true },
  '163': { host: 'imap.163.com', port: 993, secure: true },
  yahoo: { host: 'imap.mail.yahoo.com', port: 993, secure: true },
  caramail: { host: 'imap.gmx.com', port: 993, secure: true }, // caramail uses GMX servers
};

/**
 * Parse account config from .env
 * Format: name|IMAP server|port|email|password
 */
function parseAccounts() {
  const raw = process.env.ACCOUNTS;
  if (!raw) return [];

  return raw.split(',').map(entry => {
    const [name, host, port, user, pass] = entry.trim().split('|');
    return {
      name: name.trim(),
      host: host.trim(),
      port: parseInt(port.trim(), 10),
      secure: true,
      auth: {
        user: user.trim(),
        pass: pass.trim(),
      },
    };
  });
}

/**
 * Quickly build an account config from a preset
 */
function fromPreset(preset, email, password) {
  const conf = PRESETS[preset.toLowerCase()];
  if (!conf) {
    throw new Error(`Unknown preset: ${preset}, available: ${Object.keys(PRESETS).join(', ')}`);
  }
  return {
    name: preset,
    ...conf,
    auth: { user: email, pass: password },
  };
}

/**
 * Pick an IMAP config from the email domain
 */
const DOMAIN_MAP = {
  'gmail.com': 'gmail',
  'googlemail.com': 'gmail',
  'gmx.com': 'gmx',
  'gmx.net': 'gmx',
  'gmx.de': 'gmx',
  'caramail.com': 'caramail',
  'outlook.com': 'outlook',
  'hotmail.com': 'outlook',
  'live.com': 'outlook',
  'qq.com': 'qq',
  'foxmail.com': 'qq',
  '163.com': '163',
  '126.com': '163',
  'yahoo.com': 'yahoo',
  'yahoo.co.jp': 'yahoo',
};

function autoDetect(email, password) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) throw new Error(`Invalid email: ${email}`);

  const presetKey = DOMAIN_MAP[domain];
  if (presetKey) {
    return fromPreset(presetKey, email, password);
  }

  // Unknown domain, try generic imap.<domain>
  return {
    name: domain,
    host: `imap.${domain}`,
    port: 993,
    secure: true,
    auth: { user: email, pass: password },
  };
}

module.exports = { PRESETS, DOMAIN_MAP, parseAccounts, fromPreset, autoDetect };
