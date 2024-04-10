<script lang="ts">
  import { enhance } from '$app/forms';
  import type { PageData } from './$types';
  import { invalidateAll } from '$app/navigation';
  import { browser } from '$app/environment';
  import { onDestroy } from 'svelte';
  import type { Action } from 'svelte/action';

  export let data: PageData;
  export let form;

  $: pixelArt = data.pixelArt;
  let username = data.username;
  $: pixels = data.pixels;
  const colorPalette = ['#ff0000', '#ff8000', '#ffff00', '#00ff00', '#00ffff', '#0000ff', '#8000ff', '#ff00ff', '#ff0080', '#800000', '#008000', '#000080', '#808000', '#008080', '#800080', '#424242', '#ffffff', '#111111'];
  let selectedColor = colorPalette[0];
  let pixelHeight = 0;
  let pixelWidth = 0;
  let heightVar = 0;
  let widthVar = 0;


  let element_updated: Action<HTMLElement, string> = (node, current_color) => {
        return {
            update: (new_color) => {
              if (new_color == current_color) return;
                node.classList.add('glow');
                setTimeout(() => {
                    node.classList.remove('glow');
                }, 2000);
              current_color = new_color;
            },
        };
  };

  if (browser) {
    let interval: NodeJS.Timeout;

    interval = setInterval(invalidateAll, 50) ; null;

    onDestroy(() => {
      clearInterval(interval);
      invalidateAll();
    });
    function check(): any {
      if (!pixelArt) {

        console.log("william doesnt think this will run")
        return setTimeout(check, 100);
    }
        if (pixelArt.height > pixelArt.width) {
          heightVar = 560;
          widthVar = pixelArt.width * (560 / pixelArt.height);
        } else if (pixelArt.height < pixelArt.width) {
          heightVar = pixelArt.height * (560 / pixelArt.width);
          widthVar = 560;
        } else {
          heightVar = 560;
          widthVar = 560;
        }
        pixelHeight = heightVar / pixelArt.height;
        pixelWidth = widthVar / pixelArt.width;
    }
    check()
  }   

  function handleClick(event: any, pixel: { id?: number; color: any; pixelArtId?: number }) {
    if (event.buttons != 1)
      return;

    pixel.color = selectedColor;
    event.currentTarget.click();
  }
  
</script>
  
<div class="ml-4">
  <h1 class="text-2xl font-bold mb-4">Pixelart Name : <span style="color: red;">{pixelArt?.name}</span> <span style="color: black;">--</span> Creator : <span style="color: aqua;">{pixelArt?.username}</span></h1>
  <h2>Welcome: <span style="color: aqua;">{username}</span></h2>
  <a href="/pixelDashBoard" class="text-blue-500 hover:underline">
    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 inline-block align-middle" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M10.707 3.293a1 1 0 010 1.414L6.414 9H16a1 1 0 010 2H6.414l4.293 4.293a1 1 0 01-1.414 1.414l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 0z" clip-rule="evenodd" />
    </svg>
    Back
  </a>
</div>


<div class="flex flex-row justify-evenly items-center">
  <div class="flex flex-col items-center">
    <div class="flex">
      <div class="w-64 h-64 grid grid-cols-6 gap-2">
        {#each colorPalette as color}
          <div aria-hidden="true"
          class="w-10 h-10 border border-black" 
          style="background-color: {color}" 
          on:click={() => selectedColor = color}></div>
        {/each}
      </div>
    </div>
  
    <div class="flex flex-col items-center mt-4">
      <h1 class="mb-2">Selected color</h1>
      <div class="selectedColor" style="background-color: {selectedColor}; height: 20px; width: 100px;"></div>
    </div>
  </div>

  <div class="flex" style="--selectedBorderColor:{selectedColor};">
    <div class="pixelArtGrid" style="--width:{data.pixelArt.width};--height:{data.pixelArt.height};">
          {#each pixels as pixel}
            <form class="formClass" action="?/updatePixels" method="post" use:enhance>
              <input type="hidden" name="id" value="{pixel.id}">
              <input type="hidden" name="color" value="{selectedColor}">
              <button on:focus={()=>{}}
              use:element_updated={pixel.color}
              class:glow={false}
              style="height: {pixelHeight}px; width: {pixelWidth}px; background-color: {pixel.color}; cursor: crosshair;" 
              on:mouseover={(e) => handleClick(e, pixel)} 
              on:mousedown={(e) => handleClick(e, pixel)} 
              on:click={() => {}}>
              </button>
            </form>
          {/each}
    </div>
  </div>
</div>

<style>
  .pixelArtGrid {
    display: grid;
    grid-template-columns: repeat(var(--width), 1fr);
    grid-template-rows: repeat(var(--height), 1fr);
  }
  .formClass{
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .glow {
    animation: glow 1.5s 1 forwards;
  }

  @keyframes glow {
    0% {
      border: 10px solid var(--selectedBorderColor);
      -webkit-filter: invert(100%);
      filter: invert(100%);
    }
    100% {
      border: 0px solid transparent;
    }
  }
</style>