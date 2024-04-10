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
    let password = data.get("password")?.toString();

    if (username) {
      const existingUser = await prisma.user.findUnique({
        where: {
          name: username,
        }, 
      });
        

      if (existingUser) {

 
        if (password) {
          if (validatePassword(password, existingUser.salt, existingUser.hash)) {
            const token = await prisma.token.create({
              data: { userId: existingUser.id },
            });
            cookies.set("token_id", token.id, { secure: false });
            cookies.set("username", username, { secure: false });
    
            throw redirect(303, "/");
          } else {



            
            return fail(400, { password: "Invalid password" });
          }  
        }
      } else {
        
        let password = data.get("password")?.toString();
        if (password){
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

          cookies.set("token_id", token.id, { secure: false });
          cookies.set("username", newUser.name.toString());
          throw redirect(303, "/");
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
function validatePassword(inputPassword : crypto.BinaryLike, storedSalt : crypto.BinaryLike, storedHash : string) {
  const hash = crypto.pbkdf2Sync(inputPassword, storedSalt, 1000, 64, 'sha512').toString('hex');
  return storedHash === hash;
}