import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class GraphqlAuthGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        const gqlCtx = context.getArgByIndex(2);
        const token  = this.extractTokenFromCookie(request);

        if(!token) {
            throw new UnauthorizedException();
        }try{
            const payload = await this.jwtService.verifyAsync(token, {
                secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
            });
            console.log('payload',token);
            request['user'] = payload;
        } catch (err) {
            console.log('err', err);
            throw new UnauthorizedException();
        }

        return true;
    }

    private extractTokenFromCookie(request: Request): string | undefined {
        return request.cookies?.accessToken;
    }
}

