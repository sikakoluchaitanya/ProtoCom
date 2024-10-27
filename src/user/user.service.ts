import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
    constructor(private readonly prisma: PrismaService) {}

    async updateProfile(userID: number, fullname: string, avatarUrl: string) {
        if (avatarUrl) {
            return await this.prisma.user.update({
                where: {id: userID},
                data: {
                    fullname,
                    avatar: avatarUrl,
                },
            });
        }
        return  await this.prisma.user.update({
            where: {id: userID},
            data: {
                fullname
            },
        })
    }
}
