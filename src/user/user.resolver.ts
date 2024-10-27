import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { UserService } from './user.service';
import { UseGuards } from '@nestjs/common';
import { GraphqlAuthGuard } from 'src/auth/garphql-auth-gaurd';
import { User } from './user.type';
import { Request } from 'express';
import * as GraphQLUpload from 'graphql-upload/GraphQLUpload.js'
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createWriteStream } from 'fs';


@Resolver()
export class UserResolver {
    constructor( private readonly userService: UserService) {}

    @UseGuards(GraphqlAuthGuard)
    @Mutation(() => User)
    async updateProfile(
        @Args('fullname') fullname:string,
        @Args('file', { type: () => GraphQLUpload, nullable:true })
        file: GraphQLUpload.FileUpload,
        @Context() context: { req: Request},
    ) {
        const imageUrl = file ? await this.storeImageAndGetUrl(file) : null;
        const userID = context.req.user.sub; // we can access the user from request cause we have useguards which allow us to use this
        return this.userService.updateProfile(
            userID,
            fullname,
            imageUrl
        );
    }

    private async storeImageAndGetUrl(file: GraphQLUpload.FileUpload){
        const { createReadStream, filename } = await file;
        const uniqueFilename = `${uuidv4()}_${filename}`;
        const imagePath = join(process.cwd(), 'public', uniqueFilename);
        const imageUrl = `${process.env.APP_URL}/${uniqueFilename}`;
        const readStream = createReadStream();
        readStream.pipe(createWriteStream(imagePath));
        return imageUrl;
    }
}
