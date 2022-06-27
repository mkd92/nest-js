import { PrismaService } from '../prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  signup(dto: AuthDto) {
    return { msg: 'I have signed up' };
  }
  signin() {
    return { msg: 'I have signed up' };
  }
}