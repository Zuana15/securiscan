import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const SALT_BYTES = 16;
const KEY_LENGTH = 64;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const derivedKey = (await scrypt(password, salt, KEY_LENGTH)) as Buffer;
  return `scrypt$${salt.toString("base64")}$${derivedKey.toString("base64")}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [algorithm, saltValue, hashValue] = storedHash.split("$");
  if (algorithm !== "scrypt" || !saltValue || !hashValue) {
    return false;
  }

  try {
    const storedKey = Buffer.from(hashValue, "base64");
    if (storedKey.length !== KEY_LENGTH) {
      return false;
    }

    const derivedKey = (await scrypt(password, Buffer.from(saltValue, "base64"), KEY_LENGTH)) as Buffer;
    return timingSafeEqual(derivedKey, storedKey);
  } catch {
    return false;
  }
}
