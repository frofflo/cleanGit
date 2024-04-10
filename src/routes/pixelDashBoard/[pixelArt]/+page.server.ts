import { redirect, type Actions, fail } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import {PrismaClient} from "@prisma/client"

const prisma = new PrismaClient();

export const load = (async ({cookies, params}) => {
    let username = cookies.get("username")
    let id = cookies.get("token_id")
    if(!id){
        throw redirect(303, "/login")
    }
    const pixelArtName = params.pixelArt
    const pixelArt = await prisma.pixelArt.findFirst({
        where: {
            name: pixelArtName
        },
    });

    if(!pixelArt){
        throw redirect(303, "/pixelDashBoard")
    }
    
    const pixels = await prisma.pixel.findMany({where: {pixelArtId: pixelArt.id}})

    pixels.sort((a, b) => a.id - b.id);

    return {pixelArt, username, pixels};
}) satisfies PageServerLoad;

export const actions: Actions = {
  updatePixels: async({ request }) => {
    const data = await request.formData();

    const pixelId = Number(data.get("id"));
    const pixelColor = data.get("color")?.toString() ?? '';
    
    await prisma.pixel.update({where: {id: pixelId}, data: {color: pixelColor}});
  },
};

