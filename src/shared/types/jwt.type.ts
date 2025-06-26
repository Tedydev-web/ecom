export interface AccessTokenPayloadCreate {
  userId: number
  deviceId: number
  roleId: number
  roleName: string
}

export interface AccessTokenPayload extends AccessTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}

export interface RefreshTokenPayloadCreate {
  userId: number
  deviceId: number
}

export interface RefreshTokenPayload extends RefreshTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}
