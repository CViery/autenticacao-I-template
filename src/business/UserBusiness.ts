import { UserDatabase } from "../database/UserDatabase"
import { GetUsersInputDTO, GetUsersOutputDTO } from "../dtos/user/getUsers.dto"
import { LoginInputDTO, LoginOutputDTO } from "../dtos/user/login.dto"
import { SignupInputDTO, SignupOutputDTO } from "../dtos/user/signup.dto"
import { BadRequestError } from "../errors/BadRequestError"
import { NotFoundError } from "../errors/NotFoundError"
import { USER_ROLES, User } from "../models/User"
import { HashManager } from '../services/HashManeger'
import { IdGenerator } from '../services/IdGenerator'
import { TokenMenanger, TokenPayload } from '../services/TokenMenager'

export class UserBusiness {
  constructor(
    private userDatabase: UserDatabase,
    private idGenerator: IdGenerator,
    private TokenMenager: TokenMenanger,
    private HashManager : HashManager

  ) { }

  public getUsers = async (
    input: GetUsersInputDTO
  ): Promise<GetUsersOutputDTO> => {
    const { q, token } = input
    const payload = this.TokenMenager.getPaylod(token)
    
    if(payload?.role !== USER_ROLES.ADMIN){
      throw new BadRequestError("Só Admim pode acessar");
      
    }

    const usersDB = await this.userDatabase.findUsers(q)

    const users = usersDB.map((userDB) => {
      const user = new User(
        userDB.id,
        userDB.name,
        userDB.email,
        userDB.password,
        userDB.role,
        userDB.created_at
      )

      return user.toBusinessModel()
    })

    const output: GetUsersOutputDTO = users

    return output
  }

  public signup = async (
    input: SignupInputDTO
  ): Promise<SignupOutputDTO> => {
    const { name, email, password } = input

    const userDBExists = await this.userDatabase.findUserByEmail(email)

    if (userDBExists) {
      throw new BadRequestError("'email' já Cadastrado")
    }
    const id = this.idGenerator.generateId()

    const hashedPassowrd = await this.HashManager.hash(password)
    
    const newUser = new User(
      id,
      name,
      email,
      hashedPassowrd,
      USER_ROLES.NORMAL, // só é possível criar users com contas normais
      new Date().toISOString()
    )

    const newUserDB = newUser.toDBModel()
    await this.userDatabase.insertUser(newUserDB)

    const token = this.TokenMenager.createToken({
      id: newUser.getId(),
      role: newUser.getRole(),
      name: newUser.getName()
    })

    const output: SignupOutputDTO = {
      message: "Cadastro realizado com sucesso",
      token: token
    }

    return output
  }

  public login = async (
    input: LoginInputDTO
  ): Promise<LoginOutputDTO> => {
    const { email, password } = input

    const userDB = await this.userDatabase.findUserByEmail(email)

    if (!userDB) {
      throw new NotFoundError("'email' não encontrado")
    }
    const isPasswordIsValid = await this.HashManager.compare(password,userDB.password)

    if (!isPasswordIsValid) {
      throw new BadRequestError("'password' incorreta")
    }
    const user = new User{
      userDB.id,
      userDB.name,
      userDB.email,
      userDB.password,
      userDB.role,
      userDB.created_at
    }
    const payload: TokenPayload = {
      id: userDB.id,
      name: userDB.name,
      role: userDB.role
    }
    const token = this.TokenMenager.createToken(payload)
    const output: LoginOutputDTO = {
      message: "Login realizado com sucesso",
      token: token
    }

    return output
  }
}