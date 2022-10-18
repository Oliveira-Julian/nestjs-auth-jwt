import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UserService } from 'src/user/user.service';
import { UserPayload } from './models/user-payload';
import { UserToken } from './models/user-token';

@Injectable()
export class AuthService {

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService
  ) { }

  login(user: User): UserToken {
    const payload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name
    };

    const jwtToken = this.jwtService.sign(payload);

    return {
      access_token: jwtToken
    };
  }
  
  async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (isValidPassword)
        return {
          ...user,
          password: undefined
        };      
    }

    throw new Error('Email ou senha inválidos.');
  }
}
