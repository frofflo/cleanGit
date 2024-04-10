import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { PrismaClient } from '@prisma/client';
import * as crypto from "crypto"

const prisma = new PrismaClient();

export const load = (async ({ cookies }) => {
  let id = cookies.get("token_id");
  if (id) {
    throw redirect(303, "/");
  }
  return {};
}) satisfies PageServerLoad;

export const actions: Actions = {
  login: async ({ request, cookies }) => {
    const data = await request.formData();
    let username = data.get("username")?.toString();
      
    if (username) {
      const existingUser = await prisma.user.findUnique({
        where: {
          name: username,
        }, 
      });
      if (existingUser) {
        return fail(400, { password: "Username already exists" });
      } else {
        let repeatedPassword = data.get("repeatedPassword")?.toString();
        let password = data.get("password")?.toString();
        if (password == repeatedPassword && password && repeatedPassword){
          const { salt, hash } = hashPassword(password);
          const newUser = await prisma.user.create({
              data: {
                name: username,
                salt: salt,
                hash: hash,
              },
            });
            const token = await prisma.token.create({
              data: { userId: newUser.id },
            });

            cookies.set("token_id", token.id, {
              secure: false,
              path: "/"
            });
            cookies.set("username", username, {
              secure: false,
              path: "/"
            });
            
          throw redirect(303, "/");
        } else {
          return fail(400, { password: "Passwords do not match!" });
        }
      }
    }
  },
};

function hashPassword(password : crypto.BinaryLike){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { salt, hash };
}