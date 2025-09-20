import express from 'express'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import userRouter from './routes/users.routes'
import databaseService from './services/database.service'

databaseService.connect()

const app = express()
const port = 3000

//Change body to json before sending
app.use(express.json())

app.use('/users', userRouter)
app.use(defaultErrorHandler)

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
