import { Redis } from '@upstash/redis';
import jwt from 'jsonwebtoken';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

export async function handler(event, context) {
  const { path, httpMethod, body, headers } = event;
  const parsedBody = body ? JSON.parse(body) : {};

  if (httpMethod === 'POST' && path.endsWith('/register')) {
    const { username, password } = parsedBody;
    if (!username || !password) {
      return response(400, { error: 'Username and password required' });
    }
    const existing = await redis.get(`user:${username}`);
    if (existing) {
      return response(409, { error: 'User already exists' });
    }
    await redis.set(`user:${username}`, JSON.stringify({ username, password }));
    return response(201, { message: 'User registered' });
  }

  if (httpMethod === 'POST' && path.endsWith('/login')) {
    const { username, password } = parsedBody;
    if (!username || !password) {
      return response(400, { error: 'Username and password required' });
    }
    const user = await redis.get(`user:${username}`);
    if (!user) {
      return response(404, { error: 'User not found' });
    }
    let userObj;
    if (typeof user === 'string') {
      try {
        userObj = JSON.parse(user);
      } catch (e) {
        return response(500, { error: 'Corrupted user data (invalid JSON)' });
      }
    } else if (typeof user === 'object' && user !== null) {
      userObj = user; // Already an object
    } else {
      return response(500, { error: 'Corrupted user data' });
    }
    if (userObj.password !== password) {
      return response(401, { error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return response(200, { token });
  }

  if (httpMethod === 'GET' && path.endsWith('/profile')) {
    const auth = headers['authorization'] || headers['Authorization'];
    console.log('JWT_SECRET:', JWT_SECRET);
    console.log('Auth header:', auth);
    if (!auth || !auth.startsWith('Bearer ')) {
      return response(401, { error: 'Missing or invalid token' });
    }
    try {
      const token = auth.replace('Bearer ', '');
      console.log('Token:', token);
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await redis.get(`user:${decoded.username}`);
      if (!user) return response(404, { error: 'User not found' });
      const { password, ...profile } = typeof user === 'string' ? JSON.parse(user) : user;
      return response(200, { profile });
    } catch (e) {
      console.log('JWT verification error:', e);
      return response(401, { error: 'Invalid token' });
    }
  }

  return response(404, { error: 'Not found' });
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
} 