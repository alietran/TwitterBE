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

export interface ForgotPasswordDTO {
  email: string
}

export interface ResetPasswordDTO {
  password: string
  confirm_password: string
  forgot_password_token: string
}

export interface UpdateMeDTO {
  name?: string
  date_of_birth?: string
  bio?: string
  location?: string
  website?: string
  username?: string
  avatar?: string
  cover_photo?: string
}

export interface FollowUserDTO {
  follow_user_id: string
}
