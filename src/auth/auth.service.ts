import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import { ConfigService } from '@nestjs/config';
import { Request, response, Response } from 'express';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginDto, RegisterDto } from './dto';


@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService
    ) {}

    async refreshToken(req: Request, res: Response) {
        const refreshToken = req.cookies['refreshToken'];
        
        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token is missing');
        }
        let payload: any;
        
        try {
            payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }
        const userExists = await this.prisma.user.findUnique({
            where: { id: payload.sub },
        });

        if (!userExists) {
            throw new UnauthorizedException('User not found');
        }

        const expiresIn = 15000;
        const expiration = Math.floor(Date.now() / 1000) + expiresIn;
        const accessToken = await this.jwtService.signAsync(
            { ...payload, exp: expiration },
            { secret: this.configService.get<string>('JWT_ACCESS_SECRET') }
        );

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: true,
        })

        return accessToken;
    }

    private async issueTokens(user: User, res: Response) {
        const payload = { username: user.fullname, sub: user.id };
        
        const accessToken = this.jwtService.sign(
            { ...payload },
            {
                secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
                expiresIn: '150s',
            }
        );
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            expiresIn: '7d',
        }); 

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: true,
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
        });

        return { user };
    }

    async validateUser(dto: LoginDto) {
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });
        if(user && (await bcrypt.compare(dto.password, user.password))) {
            return user;
        }
        return null;
    }
    async register(dto: RegisterDto, res: Response) {
        const existingUser = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });
        if (existingUser) {
            throw new BadRequestException('User with this email already exists');
        }
        
        const hashedPassword = await bcrypt.hash(dto.password, 10);
        const user = await this.prisma.user.create({
            data: { 
                fullname: dto.fullname,
                email: dto.email,
                password: hashedPassword,
            },
        });
        return this.issueTokens(user, res);
    }

    async login( logindto: LoginDto, res: Response) {
        const user = await this.validateUser(logindto);
        if(!user) {
            throw new BadRequestException({
                invalidCredentials: 'Invalid credentials',
            });
        }
        return this.issueTokens(user, response)
    }

    async logout(res: Response) {
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return { message: 'Logged out successfully' };
    }
}
