import { Request, Response } from 'express'
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

export const registerController = async (req: Request, res: Response) => {
  const { email, password } = req.body
  try {
    const result = await userService.register({ email, password })
    res.json({
      message: 'Register success',
      result
    })
  } catch (error) {
    res.status(400).json({
      message: 'Register Failed',
      error
    })
  }
}
