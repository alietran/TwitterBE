import { NextFunction, Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { RegisterDTO } from '~/models/dto/users.dto'
import userService from '~/services/users.service'

export const loginController = (req: Request, res: Response) => {
  const { email, password } = req.body
  if (email === 'ngocdiep@gmail.com' && password === '123123') {
    res.json({
      message: 'login success'
    })
  }
  res.status(400).json({
    error: 'Login Failed'
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
