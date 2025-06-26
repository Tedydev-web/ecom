import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'

/**
 * Extracts the real IP address of the client from the request.
 * It intelligently checks various headers to work behind reverse proxies like Nginx or Cloudflare.
 */
export const Ip = createParamDecorator((_: unknown, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest<Request>()

  // List of headers to check in order of preference.
  const candidates = [
    request.headers['cf-connecting-ip'], // Cloudflare
    request.headers['x-real-ip'], // Nginx proxy
    request.headers['x-forwarded-for'], // Standard proxy header
    request.headers['x-client-ip'], // Apache httpd
    request.headers['x-cluster-client-ip'], // Kubernetes cluster
    request.headers['forwarded-for'],
    request.headers['forwarded'],
    request.connection?.remoteAddress,
    request.socket?.remoteAddress,
    request.ip,
  ].filter(Boolean)

  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      // The x-forwarded-for header can contain a comma-separated list of IPs.
      // The client's IP is typically the first one in the list.
      const ip = candidate.split(',')[0].trim()
      if (ip) {
        return ip
      }
    }
  }

  // Fallback if no IP is found.
  return '127.0.0.1'
})
