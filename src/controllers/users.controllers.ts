import { NextFunction, Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { ObjectId } from 'mongodb'
import HTTP_STATUS from '~/constants/httpStatus'
import { USER_MESSAGES } from '~/constants/message'
import { RegisterDTO, TokenPayload } from '~/models/dto/users.dto'
import User from '~/models/schemas/User.schema'
import databaseService from '~/services/database.service'
import userService from '~/services/users.service'

export const loginController = async (req: Request, res: Response) => {
  const user = req.user as User
  const user_id = user._id as ObjectId
  const result = await userService.login(user_id.toString())
  res.json({
    message: USER_MESSAGES.LOGIN_SUCCESS,
    result
  })
}

export const registerController = async (
  req: Request<ParamsDictionary, any, RegisterDTO>,
  res: Response,
  next: NextFunction
) => {
  const result = await userService.register(req.body)
  res.json({
    message: USER_MESSAGES.REGISTER_SUCCESS,
    result
  })
}

export const logoutController = async (req: Request, res: Response) => {
  const { refresh_token } = req.body
  const result = await userService.logout(refresh_token)
  return res.json(result)
}

export const emailVerifyValidator = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_email_verify as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  //IF user not found
  if (!user) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({ message: USER_MESSAGES.USER_NOT_FOUND })
  }
  // EMAIL ALREADY VERIFIED BEFORE SHOULD NOT BE ALERT ERROR
  if (user.email_verify_token === '') {
    return res.json({ message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED })
  }

  const result = await userService.verifyEmail(user_id)
  return res.json({
    message: USER_MESSAGES.EMAIL_VERIFY_SUCCESS,
    result
  })
}
