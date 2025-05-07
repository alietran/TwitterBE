import { Router } from 'express'

const usersRouter = Router()

usersRouter.get('/userList', (req, res) => {
  res.json({
    data: [
      {
        id: 1,
        name: 'test'
      }
    ]
  })
})

export default usersRouter
