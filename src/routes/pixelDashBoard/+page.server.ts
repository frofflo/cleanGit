import { fail, type Actions, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import {PrismaClient} from "@prisma/client"

const prisma = new PrismaClient();

export const load = (async({cookies}) => {
    let username = cookies.get("username")
    let id = cookies.get("token_id")
    if(!id){
        throw redirect(303, "/login")
    }
    const pixelArtList = await prisma.pixelArt.findMany({select: {name: true, id: true, width: true, height: true, userId: true, user: true, username: true, isFavoritedBy: true}})
    
    return {pixelArtList, username};
}) satisfies PageServerLoad;

export const actions: Actions = {
    create: async ({request, cookies}) => {
        let data = await request.formData();
        let username = cookies.get("username")?.toString();
        let pixelartName = data.get("pixelartName")?.toString();
        let pixelArtWidth = data.get("width")?.toString();
        let pixelArtHeight = data.get("height")?.toString();

        if(!pixelartName){
            return fail(400, {pixelartName: "Please supply a name"})
        }
        else if(await prisma.pixelArt.findFirst({where: {name: pixelartName}})){
            return fail(400, {pixelartName: "pixelArt already exists."})
        }

        const User = await prisma.user.findFirst({where: {name: username}});
        if(User && pixelArtWidth && pixelArtHeight && username){
            await prisma.pixelArt.create({data: {
                name: pixelartName,
                username: username?.toString(),
                width: parseInt(pixelArtWidth),
                height: parseInt(pixelArtHeight),
                user: { connect: { name: username } },
                Pixel: {
                    create: Array(parseInt(pixelArtWidth) * parseInt(pixelArtHeight)).fill({color: "white"})
                }
            }})
        }
        else{
            return fail(400, {pixelartName: "Unable to find user."})
        }        
        
    },
    toggleFavorite: async ({request, cookies}) => {
        let data = await request.formData();
        let username = cookies.get("username")?.toString();
        let pixelArtName = data.get("pixelArtName")?.toString();
        let pixelArtId = parseInt(data.get("pixelArtId")?.toString() ?? "0");

        const pixelArt = await prisma.pixelArt.findUnique({where: {id: pixelArtId, name: pixelArtName}, select: {isFavoritedBy: true}})
        if (!pixelArt){
            return fail(400, {pixelartName: "Unable to find pixelArt."})
        }

        const user = await prisma.user.findFirst({where: {name: username}})

        if (!user){
            return fail(400, {pixelartName: "Unable to find user."})
        }

        await prisma.pixelArt.update({where: {id: pixelArtId, name: pixelArtName}, data: {isFavoritedBy: {connect: {name: username}}}})

    },
    removeFavorite: async ({request, cookies}) => {
        let data = await request.formData();
        let username = cookies.get("username")?.toString();
        let pixelArtName = data.get("pixelArtName")?.toString();
        let pixelArtId = parseInt(data.get("pixelArtId")?.toString() ?? "0");

        const pixelArt = await prisma.pixelArt.findUnique({where: {id: pixelArtId, name: pixelArtName}, select: {isFavoritedBy: true}})
        if (!pixelArt){
            return fail(400, {pixelartName: "Unable to find pixelArt."})
        }

        const user = await prisma.user.findFirst({where: {name: username}})

        if (!user){
            return fail(400, {pixelartName: "Unable to find user."})
        }

        await prisma.pixelArt.update({where: {id: pixelArtId, name: pixelArtName}, data: {isFavoritedBy: {disconnect: {name: username}}}})

    },
};
