import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}

    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password)

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    password: hash
                }
            })
    
            delete user.password
    
            return this.signToken(user.id, user.email)
        } catch (error) {
            if (error.code === 'P2002') {
                throw new ForbiddenException(
                  'Credentials taken',
                );
              }
            throw error;
          }
    }

    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })

        if(!user) throw new ForbiddenException("Email doesn't exist!")

        const passMatch = await argon.verify(
            user.password,
            dto.password
        )

        if(!passMatch) throw new ForbiddenException("Password doesn't match!")

        return this.signToken(user.id, user.email)
    }

    async signToken(userId: number, email: string) : Promise<{access_token: string}> {
        const payload = {
            sub : userId,
            email
        }

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '7d',
            secret: this.config.get('JWT_SECRET_KEY')
        })

        return {
            access_token: token
        }
    }
}