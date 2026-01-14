import {
  split as shamirSplit,
  combine as shamirCombine,
} from "shamir-secret-sharing";
import bip39 from "bip39";

/**
 * Convert a Uint8Array to a hexadecimal string
 * @param {Uint8Array} bytes - The bytes to convert
 * @returns {string} - Hexadecimal string representation
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert a hexadecimal string to a Uint8Array
 * @param {string} hex - The hexadecimal string to convert
 * @returns {Uint8Array} - The resulting bytes
 */
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string: length must be even");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Validate a BIP39 mnemonic phrase format
 * @param {string} mnemonic - The mnemonic to validate
 * @throws {Error} - If the mnemonic format is invalid
 */
function validateMnemonic(mnemonic) {
  if (typeof mnemonic !== "string") {
    throw new Error("Mnemonic must be a string");
  }

  const trimmed = mnemonic.trim();
  if (trimmed.length === 0) {
    throw new Error("Mnemonic cannot be empty");
  }

  const words = trimmed.split(/\s+/);
  const validWordCounts = [12, 15, 18, 21, 24];

  if (!validWordCounts.includes(words.length)) {
    throw new Error(
      `Invalid mnemonic word count: ${
        words.length
      }. Expected one of: ${validWordCounts.join(", ")}`
    );
  }

  const normalizedMnemonic = words.join(" ");

  if (!bip39.validateMnemonic(normalizedMnemonic)) {
    throw new Error("Mnemonic includes invalid words in the bip39 dictionary");
  }

  return normalizedMnemonic;
}

/**
 * Validate split options
 * @param {Object} options - The options to validate
 * @param {number} options.shares - Total number of shares
 * @param {number} options.threshold - Minimum shares needed to reconstruct
 * @throws {Error} - If options are invalid
 */
function validateSplitOptions(options) {
  if (!options || typeof options !== "object") {
    throw new Error(
      "Options must be an object with shares and threshold properties"
    );
  }

  const { shares, threshold } = options;

  if (typeof shares !== "number" || !Number.isInteger(shares)) {
    throw new Error("shares must be an integer");
  }

  if (typeof threshold !== "number" || !Number.isInteger(threshold)) {
    throw new Error("threshold must be an integer");
  }

  if (shares < 2) {
    throw new Error("shares must be at least 2");
  }

  if (threshold < 2) {
    throw new Error("threshold must be at least 2");
  }

  if (threshold > shares) {
    throw new Error("threshold cannot be greater than shares");
  }

  if (shares > 255) {
    throw new Error("shares cannot exceed 255");
  }
}

/**
 * Validate shares array for combining
 * @param {string[]} shares - The shares to validate
 * @throws {Error} - If shares are invalid
 */
function validateShares(shares) {
  if (!Array.isArray(shares)) {
    throw new Error("Shares must be an array");
  }

  if (shares.length < 2) {
    throw new Error("At least 2 shares are required to reconstruct the secret");
  }

  for (let i = 0; i < shares.length; i++) {
    if (typeof shares[i] !== "string") {
      throw new Error(`Share at index ${i} must be a string`);
    }

    if (!/^[0-9a-fA-F]+$/.test(shares[i])) {
      throw new Error(`Share at index ${i} is not a valid hex string`);
    }
  }
}

/**
 * Split a BIP39 mnemonic into shares using Shamir Secret Sharing
 *
 * @param {string} mnemonic - BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
 * @param {Object} options - Split configuration
 * @param {number} options.shares - Total number of shares to create (n), must be >= 2 and <= 255
 * @param {number} options.threshold - Minimum shares needed to reconstruct (k), must be >= 2 and <= shares
 * @returns {Promise<string[]>} - Array of hex-encoded shares
 *
 * @example
 * const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
 * const shares = await split(mnemonic, { shares: 5, threshold: 3 })
 * // Returns array of 5 hex-encoded share strings
 */
export async function split(mnemonic, options) {
  // Normalize the mnemonic (trim and normalize whitespace)
  const normalizedMnemonic = validateMnemonic(mnemonic);

  validateSplitOptions(options);
  const { shares, threshold } = options;

  // Convert mnemonic to bytes
  const secretHex = bip39.mnemonicToEntropy(normalizedMnemonic);
  const secretBytes = hexToBytes(secretHex);

  // Split the secret using Shamir Secret Sharing
  const shareArrays = await shamirSplit(secretBytes, shares, threshold);

  // Convert each share to hex string for portability
  const hexShares = shareArrays.map((share) => bytesToHex(share));

  return hexShares;
}

/**
 * Reconstruct a BIP39 mnemonic from shares
 *
 * @param {string[]} shares - Array of hex-encoded shares (at least threshold amount)
 * @returns {Promise<string>} - Reconstructed BIP39 mnemonic phrase
 *
 * @example
 * const shares = ['a1b2c3...', 'd4e5f6...', 'g7h8i9...']
 * const mnemonic = await combine(shares)
 * // Returns the original mnemonic string
 */
export async function combine(shares) {
  validateShares(shares);

  // Convert hex strings back to Uint8Arrays
  const shareArrays = shares.map((share) => hexToBytes(share));

  // Reconstruct the secret using Shamir Secret Sharing
  const secretBytes = await shamirCombine(shareArrays);

  // Convert bytes back to string
  const secretHex = bytesToHex(secretBytes);
  const mnemonic = bip39.entropyToMnemonic(secretHex);

  // Validate the reconstructed mnemonic
  validateMnemonic(mnemonic);

  return mnemonic;
}

export default {
  split,
  combine,
};
