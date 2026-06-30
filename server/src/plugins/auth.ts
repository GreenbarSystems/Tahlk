import type { FastifyRequest, FastifyReply } from 'fastify';
import { jwtVerify, type JWTPayload } from 'jose';

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET!);

export interface AccessTokenPayload extends JWTPayload {
  sub: string;   // providerId
  orgId: string;
  role: string;
}

export async function verifyAccessToken(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const auth = request.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    await reply.code(401).send({ error: 'Missing authorization header' });
    return;
  }
  try {
    const { payload } = await jwtVerify<AccessTokenPayload>(
      auth.slice(7),
      SECRET,
    );
    request.provider = payload;
  } catch {
    await reply.code(401).send({ error: 'Invalid or expired token' });
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    provider?: AccessTokenPayload;
  }
}
