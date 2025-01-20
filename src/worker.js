import { WorkerEntrypoint } from 'cloudflare:workers';

export class AuthWorker extends WorkerEntrypoint {
	async fetch(request, env, ctx) {
		return new Response(null, { status: 404 });
	}

	async verifyAuth(oauthId, properties = null) {
		if (!oauthId) return { auth: false, session: false };
		const session = await this.env.AUTH_SESSIONS.get(oauthId);
		if (!session) return { auth: false, session: false };
		const user = await this.env.AUTH_USERS.get(session, 'json');
		if (properties && !(await this.env.UTILS.evaluateQuery(user, properties))) return { auth: false, session: true };
		return { auth: true, session: true, data: user };
	}
}

// Utility functions for setting and removing cookies
function setCookie(name, value, maxAge = 3600) {
	return `${name}=${value}; Path=/; Domain=tablerus.es; HttpOnly; Secure; Max-Age=${maxAge}; SameSite=None`;
}

function removeCookie(name) {
	return `${name}=; Path=/; Domain=tablerus.es; HttpOnly; Secure; Max-Age=0; SameSite=None`;
}

export default {
	async fetch(request, env, ctx) {
		try {
			let url = request.url;
			if (url.endsWith('/')) url = url.substring(0, url.length - 1);
			url = new URL(url);
			const pathArray = url.pathname.split('/');
			const path = pathArray[pathArray.length - 1];

			if (path === 'login') {
				// Check if user already has a valid session
				const cookies = request.headers.get('Cookie') || '';
				const oauthId = cookies.match(/oauthId=([^;]*)/)?.[1];
				const urlParams = new URL(request.url).searchParams;
				const customRedirectUrl = urlParams.get('redirect');

				if (oauthId) {
					const session = await env.AUTH_SESSIONS.get(oauthId);
					if (session) {
						if (customRedirectUrl) return Response.redirect(customRedirectUrl);
						else return new Response('Already logged in', { status: 200 });
					}
				}

				// Redirect to Google Auth screen
				const redirectUri = url.protocol + '//' + url.hostname + url.pathname.substring(0, url.pathname.length - 5) + 'redirect';
				const state = customRedirectUrl ? `&state=${customRedirectUrl}` : '';
				const googleAuthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=email%20profile&access_type=offline${state}`;
				return Response.redirect(googleAuthUrl, 302);
			}

			if (path === 'redirect') {
				// Handle Google OAuth redirect
				const urlParams = new URL(request.url).searchParams;
				const code = urlParams.get('code');
				const customRedirectUrl = urlParams.get('state');

				if (!code) return new Response('Missing authorization code', { status: 400 });

				// Exchange authorization code for access token
				const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({
						code,
						client_id: env.GOOGLE_CLIENT_ID,
						client_secret: env.GOOGLE_CLIENT_SECRET,
						redirect_uri: url.protocol + '//' + url.hostname + url.pathname,
						grant_type: 'authorization_code',
					}).toString(),
				});

				if (!tokenResponse.ok)
					return new Response('Failed to exchange code for token: ' + JSON.stringify(await tokenResponse.json()), { status: 401 });

				const tokenData = await tokenResponse.json();
				const accessToken = tokenData.access_token;

				// Fetch user info from Google API
				const userResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo?alt=json', {
					headers: { Authorization: `Bearer ${accessToken}` },
				});

				if (!userResponse.ok) {
					return new Response('Failed to fetch user info', { status: 401 });
				}

				const userData = await userResponse.json();
				const oauthId = await env.UTILS.generateID(64);

				// Store session in KV
				await env.AUTH_SESSIONS.put(oauthId, userData.id, { expirationTtl: 3600 * 24 * 7 });
				const user = JSON.parse((await env.AUTH_USERS.get(userData.id)) || '{}');
				const data = { provider: 'google', organization: userData.email.split('@')[1], ...userData, ...user };
				await env.AUTH_USERS.put(userData.id, JSON.stringify(data));

				const response = new Response('Login successful', { status: customRedirectUrl ? 302 : 200 });
				response.headers.set('Set-Cookie', setCookie('oauthId', oauthId));
				if (customRedirectUrl) response.headers.set('Location', customRedirectUrl);
				return response;
			}

			if (path === 'logout') {
				// Remove session cookie
				const cookies = request.headers.get('Cookie') || '';
				const oauthId = cookies.match(/oauthId=([^;]*)/)?.[1];

				if (oauthId) await env.AUTH_SESSIONS.delete(oauthId);

				const urlParams = new URL(request.url).searchParams;
				const login = urlParams.get('login') == '1';
				const customRedirectUrl = urlParams.get('redirect');

				const response = new Response('Logged out', { status: login || customRedirectUrl ? 302 : 200 });
				response.headers.set('Set-Cookie', removeCookie('oauthId'));
				if (login || customRedirectUrl)
					response.headers.set(
						'Location',
						login
							? 'https://workers.tablerus.es/auth/login' + (customRedirectUrl ? '?redirect=' + encodeURIComponent(customRedirectUrl) : '')
							: customRedirectUrl
					);
				return response;
			}

			return new Response(null, { status: 404 });
		} catch (error) {
			console.error(error);
			return new Response('Internal Server Error', { status: 500 });
		}
	},
};
