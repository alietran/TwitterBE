import { JwtPayload } from 'jsonwebtoken'

export interface loginDTO {
  email: string
  password: string
}

export interface VerifyEmailDTO {
  email_verify_token: string
}

export interface RegisterDTO {
  email: string
  password: string
  confirm_password: string
  name: string
  date_of_birth: Date
}

export interface TokenPayload extends JwtPayload {
  user_id: string
  token_type: string
}
