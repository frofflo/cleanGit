<script>
	export let data;

	$: username = data.username;
</script>

<div class="container h-full mx-auto flex justify-center items-center">
	<div class="space-y-5">

		<main>
			<h1>Welcome, {username}!</h1>
			<p>Thank you for visiting our website.</p>
			<a href="/pixelDashBoard" class="text-blue-500 hover:underline">Go to Pixel Dashboard</a>
		</main>
		<!-- <ul>
			<li><code class="code">/src/routes/+layout.svelte</code> - barebones layout</li>
			<li><code class="code">/src/app.postcss</code> - app wide css</li>
			<li>
				<code class="code">/src/routes/+page.svelte</code> - this page, you can replace the contents
			</li>
		</ul> -->
	</div>
</div>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		height: 100vh;
		text-align: center;
	}

	h1 {
		font-size: 2rem;
		margin-bottom: 1rem;
	}

	p {
		font-size: 1.2rem;
	}
</style>
