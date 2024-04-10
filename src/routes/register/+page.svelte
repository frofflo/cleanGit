<script lang="ts">
    import { enhance } from "$app/forms";
  
    export let form: { username?: string , password?: string} = {};

</script>

<div class="flex flex-col justify-evenly items-center min-h-screen">
    <div>
        <h1 class="text-6xl font-bold" style="margin-top:-20vh;">Register</h1>
    </div>
    <div class="bg-blue-200 rounded-lg p-8 variant-glass-surface" style="margin-top:-40vh;">
        <form method="POST" class="flex flex-col" action="?/login" use:enhance>
            <label>
                Username
                <input class="input" name="username" type="text">
            </label>
            <label>
                Password
                <input class="input" name="password" type="password">
            </label>
            <label>
                Repeat password
                <input class="input" name="repeatedPassword" type="password">
            </label>
            {#if form?.password}
                <span class="errorMessage">{form.password}</span>
            {/if}
            <button class="mt-4 mx-auto bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-1/2">Register</button>
            <a class="mt-5" href="/Login">Already have an account?</a>
        </form>
    </div>
</div>

<style>
    .errorMessage{
        color: red;
    }
    .input:focus {
        outline: none;
        border-color: transparent;
        box-shadow: none;
    }
</style>