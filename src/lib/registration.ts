const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface RegistrationInput {
  name: string;
  email: string;
  password: string;
}

export function canRegisterLocally(): boolean {
  return (
    process.env.NODE_ENV === "development" &&
    process.env.SECURISCAN_ALLOW_REGISTRATION === "true"
  );
}

export function validateRegistration(value: unknown): RegistrationInput | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const { name, email, password } = value as Record<string, unknown>;
  if (typeof name !== "string" || typeof email !== "string" || typeof password !== "string") {
    return null;
  }

  const normalizedName = name.trim().replace(/\s+/g, " ");
  const normalizedEmail = email.trim().toLowerCase();
  const hasLetter = /[a-z]/i.test(password);
  const hasNumber = /\d/.test(password);

  if (
    normalizedName.length < 2 ||
    normalizedName.length > 80 ||
    normalizedEmail.length > 254 ||
    !EMAIL_PATTERN.test(normalizedEmail) ||
    password.length < 8 ||
    password.length > 128 ||
    !hasLetter ||
    !hasNumber
  ) {
    return null;
  }

  return { name: normalizedName, email: normalizedEmail, password };
}
