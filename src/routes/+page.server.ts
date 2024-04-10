import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load = (async ({cookies}) => {
    let username = cookies.get("username")
    let id = cookies.get("token_id")
    if(!id){
        throw redirect(303, "/Login")    
    }
    return {username};
}) satisfies PageServerLoad;
