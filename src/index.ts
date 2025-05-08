import express from 'express'
import userRouter from './routes/users.routes'
import databaseService from './services/database.service'
const app = express()
const port = 3000

//Change body to json before sending
app.use(express.json())

app.use('/users', userRouter)
databaseService.connect()

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
