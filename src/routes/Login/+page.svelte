<script lang="ts">
    import { enhance } from "$app/forms";
  
    export let form: { username?: string , password?: string} = {};

</script>

<div class="flex justify-center items-center min-h-screen">
    <div class="bg-blue-200 rounded-lg p-8 variant-glass-surface" style="margin-top: -10%">
        <form method="POST" action="?/login" use:enhance>
            <label>
                Username
                <input class="input" name="username" type="login">
            </label>
            <label>
                Password
                <input class="input" name="password" type="password">
            </label>
            <button class="mt-4">Log in</button>
    
            {#if form?.password}
                <span class="errorMessage">{form.password}</span>
            {/if}
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