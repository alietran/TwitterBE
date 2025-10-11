import { TokenPayload } from './models/dto/users.dto'
import User from './models/schemas/User.schema'

declare module 'express' {
  interface Request {
    user?: User
    decoded_authorization?: TokenPayload
    decoded_refresh_token?: TokenPayload
    decoded_email_verify?: TokenPayload
    decode_forgot_password_token?: TokenPayload
  }
}
