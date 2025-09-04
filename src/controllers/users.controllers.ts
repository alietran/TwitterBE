import { NextFunction, Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { ObjectId } from 'mongodb'
import { RegisterDTO } from '~/models/dto/users.dto'
import User from '~/models/schemas/User.schema'
import userService from '~/services/users.service'

export const loginController = async (req: Request, res: Response) => {
  const user = req.user as User
  const user_id = user._id as ObjectId
  const result = await userService.login(user_id.toString())
  res.json({
    message: 'Login success',
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
    message: 'Register success',
    result
  })
}
