import { Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { ObjectId } from 'mongodb'
import HTTP_STATUS from '~/constants/httpStatus'
import { USER_MESSAGES } from '~/constants/message'
import {
  FollowUserDTO,
  ForgotPasswordDTO,
  loginDTO,
  RegisterDTO,
  ResetPasswordDTO,
  TokenPayload,
  UpdateMeDTO,
  VerifyEmailDTO
} from '~/models/dto/users.dto'
import User, { UserVerifyStatus } from '~/models/schemas/User.schema'
import databaseService from '~/services/database.service'
import userService from '~/services/users.service'

export const loginController = async (req: Request<ParamsDictionary, any, loginDTO>, res: Response) => {
  const user = req.user as User
  const user_id = user._id as ObjectId
  const result = await userService.login({ user_id: user_id.toString(), verify: user.verify })
  res.json({
    message: USER_MESSAGES.LOGIN_SUCCESS,
    result
  })
}

export const registerController = async (req: Request<ParamsDictionary, any, RegisterDTO>, res: Response) => {
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

export const emailVerifyController = async (req: Request<ParamsDictionary, any, VerifyEmailDTO>, res: Response) => {
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

export const resendEmailVerifyController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  //IF user not found
  if (!user) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({ message: USER_MESSAGES.USER_NOT_FOUND })
  }
  // EMAIL ALREADY VERIFIED BEFORE SHOULD NOT BE ALERT ERROR
  if (user.verify === UserVerifyStatus.Verified) {
    return res.json({ message: USER_MESSAGES.EMAIL_ALREADY_VERIFIED })
  }
  const result = await userService.resendVerifyEmail(user_id)
  return res.json(result)
}

export const forgotPasswordController = async (
  req: Request<ParamsDictionary, any, ForgotPasswordDTO>,
  res: Response
) => {
  const { _id, verify } = req.user as User
  const result = await userService.forgotPassword({ user_id: (_id as ObjectId).toString(), verify })
  return res.json({ result })
}

export const verifyForgotPasswordController = async (req: Request, res: Response) => {
  return res.json({ message: USER_MESSAGES.VERIFY_FORGOT_PASSWORD_SUCCESS })
}

export const resetPasswordController = async (req: Request<ParamsDictionary, any, ResetPasswordDTO>, res: Response) => {
  const { user_id } = req.decode_forgot_password_token as TokenPayload
  const result = await userService.resetPassword(user_id, req.body.password)
  return res.json({ result })
}

export const getMeController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await userService.getMe(user_id)
  return res.json({
    message: USER_MESSAGES.GET_ME_SUCCESS,
    result: user
  })
}

export const getProfileController = async (req: Request, res: Response) => {
  const { username } = req.params
  const user = await userService.getProfile(username)
  return res.json({
    message: USER_MESSAGES.GET_PROFILE_SUCCESS,
    result: user
  })
}

export const updateMeController = async (req: Request<ParamsDictionary, any, UpdateMeDTO>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const user = await userService.updateMe(user_id, req.body)
  return res.json({
    message: USER_MESSAGES.UPDATE_ME_SUCCESS,
    result: user
  })
}

export const followUserController = async (req: Request<ParamsDictionary, any, FollowUserDTO>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { follow_user_id } = req.body
  const result = await userService.followUser(user_id, follow_user_id)
  return res.json(result)
}
