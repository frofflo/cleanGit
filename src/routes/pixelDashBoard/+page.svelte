<script lang="ts">
	import { enhance } from '$app/forms';
    import type { PageData } from './$types';
    import { invalidateAll } from '$app/navigation';
    import { browser } from '$app/environment';
    import { onDestroy } from 'svelte';
    
    export let data: PageData;
    export let form;

    $: pixelarts = data?.pixelArtList;

    if (browser) {
        let interval: NodeJS.Timeout;

        interval = setInterval(invalidateAll, 1000) ; null;

        onDestroy(() => {
            clearInterval(interval);
            invalidateAll();
        });
    }   

	$: username = data.username;

    let width = 8;
    let height = 8;
    let pixelartName = '';

    function isFav(pixelart: any, username: string|undefined): boolean {
        if (!username) return false;
        if (!pixelart.isFavoritedBy) return false;
        for (let i = 0; i < pixelart.isFavoritedBy.length; i++) {
            if (pixelart.isFavoritedBy[i].name == username) {
                return true;
            }
        }
        return false
    }
</script>

<div class="flex flex-row justify-evenly">
    <div class="flex flex-col items-center">
        <h1 class="text-2xl font-bold mb-4">Welcome - {username}</h1>
        <form class="form bg-glass rounded-lg p-4" action="?/create" method="post" use:enhance style="max-width: 300px;">
            <div class="flex flex-col">
                <label class="text-white mb-2" for="pixelartNameInput">Pixelart Name:</label>
                <input class="input mb-2" type="text" name="pixelartName" bind:value={pixelartName}>
                <label class="text-white mb-2" for="widthInput">Width: {width}</label>
                <input class="input mb-2" type="range" name="width" min="8" max="16" bind:value={width}>
                <label class="text-white mb-2" for="heightInput">Height: {height}</label>
                <input class="input mb-2" type="range" name="height" min="8" max="16" bind:value={height}>
                <button class="bg-blue-500 text-white px-4 py-2 rounded">Create pixelart</button>
                {#if form?.pixelartName}
                    <span>{form.pixelartName}</span>
                {/if}
            </div>
        </form>
    </div>

    <div>
        <h1 class="text-2xl font-bold mb-4 flex flex-col items-center">Favorites</h1>
        <div class="flex flex-col items-center" style="background-color: #3B4661; overflow-y:scroll; border: 5px solid #333d54; border-radius: 8px; padding: 25px; max-height: 500px;">
            <ul class="flex flex-col items-end justify-evenly">
                {#each pixelarts as pixelart}
                    {#if isFav(pixelart, username)}
                    <div class="flex flex-row items-center justify-evenly" style="margin-bottom:10px;">
                        <li><a href="/pixelDashBoard/{pixelart.name}">{pixelart.name} - {pixelart.width} x {pixelart.height}</a></li>
                        <form action="?/removeFavorite" method="post" style="margin-left: 20px;">
                            <input type="hidden" name="pixelArtName" value="{pixelart.name}">
                            <input type="hidden" name="pixelArtId" value="{pixelart.id}">
                            <button class="bg-blue-500 text-white px-4 py-2 rounded">
                                <i class="fa-solid fa-star"></i>
                            </button>                    
                        </form>
                    </div>
                    {/if}
                {/each}
            </ul>
        </div>
    </div>

    <div>
        <h1 class="text-2xl font-bold mb-4 flex flex-col items-center">Your Pixelarts</h1>
        <div class="flex flex-col items-center" style="background-color: #3B4661; overflow-y:scroll; border: 5px solid #333d54; border-radius: 8px; padding: 25px; max-height: 500px;">
            <ul class="flex flex-col items-end justify-evenly">
            {#each pixelarts as pixelart}
                {#if !isFav(pixelart, username) && pixelart.username == username}
                <div class="flex flex-row items-center justify-evenly" style="margin-bottom:10px;">
                    <li><a href="/pixelDashBoard/{pixelart.name}">{pixelart.name} - {pixelart.width} x {pixelart.height}</a></li>
                    <form action="?/toggleFavorite" method="post" style="margin-left: 20px;">
                        <input type="hidden" name="pixelArtName" value="{pixelart.name}">
                        <input type="hidden" name="pixelArtId" value="{pixelart.id}">
                        <button class="bg-blue-500 text-white px-4 py-2 rounded">
                            <i class="fa-regular fa-star"></i>
                        </button>
                    </form>
                </div>
                {/if}
            {/each}
        </ul>
    </div>

    </div>
    
    <div>
        <h1 class="text-2xl font-bold mb-4 flex flex-col items-center">Explore</h1>
        <div class="flex flex-col items-center" style="background-color: #3B4661; overflow-y:scroll; border: 5px solid #333d54; border-radius: 8px; padding: 25px; max-height: 500px;">
            <ul class="flex flex-col items-end justify-evenly">
                {#each pixelarts as pixelart}
                    {#if !isFav(pixelart, username) && pixelart.username != username}
                    <div class="flex flex-row items-center justify-evenly" style="margin-bottom:10px;">
                        <li><a href="/pixelDashBoard/{pixelart.name}">{pixelart.name} - {pixelart.width} x {pixelart.height}</a></li>
                        <form action="?/toggleFavorite" method="post" style="margin-left: 20px;">
                            <input type="hidden" name="pixelArtName" value="{pixelart.name}">
                            <input type="hidden" name="pixelArtId" value="{pixelart.id}">
                            <button class="bg-blue-500 text-white px-4 py-2 rounded">
                                <i class="fa-regular fa-star"></i>
                            </button>
                        </form>
                    </div>
                    {/if}
                {/each}
            </ul>
        </div>
    </div>
</div>