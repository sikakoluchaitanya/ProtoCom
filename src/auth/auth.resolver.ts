import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { LoginResponse, RegisterResponse } from './types';
import { BadRequestException } from '@nestjs/common';
import { Response, Request } from 'express';


@Resolver()
export class AuthResolver {
    constructor( private readonly authservice: AuthService) {}

    @Mutation(() => RegisterResponse)
    async register (
        @Args('registerInput') registerDto: RegisterDto,
        @Context() context: { res: Response },
    ) {
        if (registerDto.password !== registerDto.confirmPassword){
            throw new BadRequestException({
                confirmPassword: 'Password and confirm password are not the same.'
            })
        }
        const { user } = await this.authservice.register(registerDto, context.res);
        return { user };
    }

    @Mutation(() => LoginResponse)
    async login(
        @Args('loginInput') loginDto: LoginDto,
        @Context() context: { res: Response},
    ) {
        return this.authservice.login(loginDto, context.res)
    }
    
    @Mutation(() => String)
    async logout(@Context() context: {res: Response}) {
        return this.authservice.logout(context.res);
    }

    @Mutation(() => String)
    async refreshToken(@Context() context: { req: Request; res: Response }) {
        try {
            return this.authservice.refreshToken(context.req, context.res);
        }catch (error){
            throw new BadRequestException(error.message);
        }
    }

}
