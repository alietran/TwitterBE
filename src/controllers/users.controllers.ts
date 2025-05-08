import { Request, Response } from 'express'

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
