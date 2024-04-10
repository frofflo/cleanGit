<script lang="ts">
    let clientHeight = 0;
    import './variables.css';
    import '../app.postcss';
    import '@fortawesome/fontawesome-free/css/all.css';
    import type { LayoutData } from './$types';
    import { invalidateAll } from '$app/navigation';
    import { LightSwitch } from '@skeletonlabs/skeleton';
    
    export let data: LayoutData;

    let showMenu = false;

    $: username = data.username;

    function toggleMenu() {
        showMenu = !showMenu;
        invalidateAll();
    }
</script>

<body class="">
    <ul bind:clientHeight={clientHeight} class="variant-glass-surface">
        <li class="flex flex-row items-center">
            <div class="homePageLinkContainer">
                <a class="homePageLink" href="/">Homepage</a>
            </div>
            <div>
                <LightSwitch/>
            </div>
        </li>
        <button class="hamburger-menu" on:click={toggleMenu}>
            <span class="line"></span>
            <span class="line"></span>
            <span class="line"></span>
        </button>
    </ul>
    
    <div class="slotDiv">
        <slot />
        <div class="menu-list" on:click={toggleMenu} class:showMenu={showMenu} aria-hidden="true">
            {#if !username}
                <li><a class="linkClass" href="/Login">Login</a></li>
            {/if}
            {#if username}
                <li><a class="linkClass" href="/Logout">Logout</a></li>
            {/if} 
        </div>
    </div>
</body>

<style>
    :global(*){
        font-family: Georgia, 'Times New Roman', Times, serif;
    }  
    body{
        margin: 0;
        padding: 0;
        width: 100vw;
        height: 100vh;
        overflow: hidden;
    }
    .slotDiv{
        height: calc(100vh - clientHeight);
        width: 100vw;
        position: relative;
    }
    ul {
        list-style-type: none;
        margin: 0;
        padding: 0;
        overflow: hidden;
        height: 8vh;
        display: flex;
        justify-content: space-between;
        align-items: center;    
    }
    .homePageLinkContainer {
        font-size: 2em;
        border-radius: 5px;
    }
    .homePageLink{
        height: 8vh;
        padding: 0 2.5vh 0 2.5vh;
        display: flex;
        align-items: center; 
        background: no-repeat center;
        border-radius: 5px;
    }
    .homePageLink:hover{
        background-color: rgba(255, 255, 255, 0.1);
    }
    .linkClass{
        padding: 1vh 2.5vh 1vh 2.5vh;
        align-items: center; 
        border-radius: 5px;
    }
    .linkClass:hover{
        background-color: rgba(255, 255, 255, 0.1);
    }
    .linkClass:focus, .homePageLink:focus{
        outline: none;
        background-color: rgba(255, 255, 255, 0.3);
    }
    .linkClass:active{
        scale:0.9;
        transform: translateY(-0.2px);
    }
    a {
        text-decoration: none;
    }
    .hamburger-menu {
        margin-right: 1rem;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        width: 30px;
        height: 20px;
        border: none;
        cursor: pointer;
        background-color: transparent;
    }
    .menu-list {
        display: flex;
        text-align: center;
        width: 100vw;
        height: calc(100vh - 8vh); 
        position: absolute;
        top: 0vh; 
        left: 0;
        background-color: rgba(0, 0, 0, 0.5);
        padding: 1rem;
        list-style-type: none;
        display: none;
        z-index: 10;
    }

    .hamburger-menu .line {
        width: 100%;
        height: 2px;
        margin-bottom: 4px;
        background-color: var(--white-yellow);
    }

    .showMenu {
        display: block;
    }

    .menu-list li {
        margin-bottom: 0.5rem;
    }

    .menu-list li a {
        color: white;
        text-decoration: none;
    }
</style>

