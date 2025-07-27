import jwt from 'jsonwebtoken'
import { TokenType } from '~/constants/enum'
import { RegisterDTO } from '~/models/dto/users.dto'
import User from '~/models/schemas/User.schema'
import { hashPassword } from '~/utils/crypto'
import { signToken } from '~/utils/jwt'
import databaseService from './database.service'

class UsersService {
  private signAccessToken(user_id: string) {
    return signToken({
      payload: { user_id, token_type: TokenType.AccessToken },
      options: {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRATION_IN as jwt.SignOptions['expiresIn']
      }
    })
  }

  private signRefreshToken(user_id: string) {
    return signToken({
      payload: { user_id, token_type: TokenType.RefreshToken },
      options: {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRATION_IN as jwt.SignOptions['expiresIn']
      }
    })
  }

  async register(payload: RegisterDTO) {
    const result = await databaseService.users.insertOne(
      new User({
        ...payload,
        password: hashPassword(payload.password)
      })
    )

    const user_id = result.insertedId.toString()

    const [accessToken, refreshToken] = await Promise.all([
      this.signAccessToken(user_id),
      this.signRefreshToken(user_id)
    ])
    return {
      accessToken,
      refreshToken
    }
  }

  async checkEmailExists(email: string) {
    const user = await databaseService.users.findOne({ email })
    return Boolean(user)
  }
}

const userService = new UsersService()
export default userService
