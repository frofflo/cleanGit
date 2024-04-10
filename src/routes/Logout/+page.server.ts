import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load = (async ({cookies}) => {
        cookies.delete("token_id")
        cookies.delete("username");
        throw redirect(303, "/");
}) satisfies PageServerLoad;