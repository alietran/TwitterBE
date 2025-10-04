import jwt from 'jsonwebtoken'

export const signToken = ({
  payload,
  privateKey,
  options = {
    algorithm: 'HS256',
    expiresIn: '1h'
  }
}: {
  payload: string | Buffer | object
  privateKey: string
  options?: jwt.SignOptions
}) => {
  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, privateKey, options, (err, token) => {
      if (err) {
        return reject(err)
      }
      resolve(token as string)
    })
  })
}

export const verifyToken = ({ token, key }: { token: string; key: string }) => {
  return new Promise<jwt.JwtPayload>((resolve, reject) => {
    console.log('key', key)
    jwt.verify(token, key, (err, decoded) => {
      if (err) {
        return reject(err)
      }
      resolve(decoded as jwt.JwtPayload)
    })
  })
}
