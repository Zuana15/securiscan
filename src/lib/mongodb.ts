import dns from "node:dns";
import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI?.trim();
const MONGODB_DNS_SERVERS = process.env.MONGODB_DNS_SERVERS?.trim();
const MONGODB_FALLBACK_HOSTS = process.env.MONGODB_FALLBACK_HOSTS?.trim();
const MONGODB_FALLBACK_REPLICA_SET = process.env.MONGODB_FALLBACK_REPLICA_SET?.trim();

if (MONGODB_DNS_SERVERS) {
  const servers = MONGODB_DNS_SERVERS.split(",").map((server) => server.trim()).filter(Boolean);
  if (servers.length) {
    try {
      dns.setServers(servers);
    } catch (error) {
      console.warn("Ignoring invalid MONGODB_DNS_SERVERS configuration", error);
    }
  }
}

interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
}

declare global {
  var mongoose: MongooseCache | undefined;
}

const cached: MongooseCache = global.mongoose ?? { conn: null, promise: null };

if (!global.mongoose) {
  global.mongoose = cached;
}

export function isMongoConfigured(): boolean {
  return Boolean(MONGODB_URI);
}

function buildAtlasFallbackUri(uri: string): string {
  if (!MONGODB_FALLBACK_HOSTS || !MONGODB_FALLBACK_REPLICA_SET) {
    return uri;
  }

  if (!uri.startsWith("mongodb+srv://")) {
    return uri;
  }

  const match = uri.match(/^mongodb\+srv:\/\/([^@]+)@[^/?#]+(\/[^?#]*)?(\?[^#]*)?$/);
  if (!match) {
    throw new Error("MONGODB_URI is not a valid Atlas SRV connection string.");
  }

  const hosts = MONGODB_FALLBACK_HOSTS
    .split(",")
    .map((host) => host.trim())
    .filter(Boolean);
  if (
    !hosts.length ||
    hosts.some((host) => !/^[a-z0-9.-]+:\d{1,5}$/i.test(host)) ||
    !/^[a-z0-9-]+$/i.test(MONGODB_FALLBACK_REPLICA_SET)
  ) {
    throw new Error("The MongoDB Atlas fallback host configuration is invalid.");
  }

  const path = match[2] || "/";
  const options = new URLSearchParams(match[3]?.slice(1));
  options.set("authSource", options.get("authSource") ?? "admin");
  options.set("replicaSet", MONGODB_FALLBACK_REPLICA_SET);
  options.set("tls", "true");
  options.set("retryWrites", options.get("retryWrites") ?? "true");
  options.set("w", options.get("w") ?? "majority");

  return `mongodb://${match[1]}@${hosts.join(",")}${path}?${options.toString()}`;
}

async function dbConnect(): Promise<typeof mongoose> {
  if (!MONGODB_URI) {
    throw new Error('Set MONGODB_URI in .env.local before enabling scan persistence.');
  }

  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5_000,
      // Atlas is reachable over IPv4 on networks where Node's IPv6 route can
      // fail during the TLS handshake (notably on some Windows/ISP setups).
      family: 4 as const,
    };

    const connectionUri = buildAtlasFallbackUri(MONGODB_URI);
    cached.promise = mongoose.connect(connectionUri, opts).then((mongoose) => {
      return mongoose;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

export default dbConnect;
