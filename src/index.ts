import express, { NextFunction, Request, Response } from 'express'
import userRouter from './routes/users.routes'
import databaseService from './services/database.service'
const app = express()
const port = 3000

//Change body to json before sending
app.use(express.json())

app.use('/users', userRouter)
databaseService.connect()

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.log('error', err.message)
  res.status(400).json({
    error: err.message || 'An unexpected error occurred'
  })
})
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
