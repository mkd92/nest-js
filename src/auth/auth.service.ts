import { PrismaService } from '../prisma/prisma.service';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // generate passsword
    const hash = await argon.hash(dto.password);
    // save new user
    try {
      const user = await this.prisma.user.create({
        data: { email: dto.email, hash },
      });
      delete user.hash;
      // return saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('credentials taken');
        }
        throw error;
      }
    }
  }
  async signin(dto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // if user doesnt exist thow exception
    if (!user) throw new ForbiddenException('Credentials Incorrect');
    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('Credentials Incorrect');
    // send back user
    delete user.hash;
    return user;
  }
}
