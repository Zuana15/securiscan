import { Schema, model, models, type Model } from "mongoose";

export const USER_ROLES = ["owner", "analyst", "viewer"] as const;
export type UserRole = (typeof USER_ROLES)[number];

export interface StoredUser {
  email: string;
  name: string;
  passwordHash: string;
  role: UserRole;
}

const userSchema = new Schema<StoredUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      index: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    name: { type: String, required: true, trim: true, maxlength: 80 },
    passwordHash: { type: String, required: true, select: false },
    role: { type: String, required: true, enum: USER_ROLES, default: "analyst" },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

const User: Model<StoredUser> =
  (models.User as Model<StoredUser> | undefined) ?? model<StoredUser>("User", userSchema);

export default User;
