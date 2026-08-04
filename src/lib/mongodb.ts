import dns from "node:dns";
import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI?.trim();
const MONGODB_DNS_SERVERS = process.env.MONGODB_DNS_SERVERS?.trim();

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
    };

    cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => {
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
