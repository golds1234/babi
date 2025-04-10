// @ts-ignore
import { connect } from 'cloudflare:sockets';

// --- Konfigurasi Awal ---

// Default User ID (sebaiknya diatur melalui Environment Variable 'UUID')
// Cara generate UUID Anda sendiri:
// [Windows] Tekan "Win + R", ketik cmd, jalankan: Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4'; // Contoh UUID

// Daftar Proxy IP Default (bisa di-override dengan Environment Variable 'PROXY_IP')
// Digunakan untuk fallback jika koneksi langsung gagal atau untuk menyediakan alternatif
// Contoh: 'cdn.xn--b6gac.eu.org' atau domain/IP lain yang mengarah ke worker Anda.
//             Sangat disarankan *tidak* menggunakan domain pihak ketiga acak
//             kecuali Anda mengontrolnya atau tahu persis perilakunya.
const defaultProxyIPs = ['cdn.xn--b6gac.eu.org']; // Contoh: IP/Domain CDN Anda

// URL Default untuk DNS over HTTPS (DoH) untuk proxy UDP (port 53)
// Bisa di-override dengan Environment Variable 'DNS_RESOLVER_URL'
let dohURL = 'https://cloudflare-dns.com/dns-query'; // Cloudflare sebagai default
// Alternatif lain: 'https://dns.google/dns-query'

// Pilihan Proxy IP: Ambil dari env atau pilih secara acak dari default
let proxyIP = defaultProxyIPs[Math.floor(Math.random() * defaultProxyIPs.length)];

// Daftar port standard untuk VLESS over WS (non-TLS)
const httpPorts = new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
// Daftar port standard untuk VLESS over WSS (TLS)
const httpsPorts = new Set([443, 8443, 2053, 2096, 2087, 2083]);

// Daftar hostname target untuk fitur reverse proxy di default route (PERHATIAN: Gunakan dengan hati-hati!)
// Ini akan meneruskan request yang tidak cocok dengan path lain ke salah satu host ini.
// Sebaiknya gunakan domain yang Anda kontrol atau pahami sepenuhnya.
const fallbackProxyHostnames = ['www.wikipedia.org']; // Contoh, lebih aman daripada domain acak

// --- Validasi Awal ---

// Periksa apakah UUID default valid (ini hanya pemeriksaan saat skrip dimuat)
if (!isValidUUID(userID)) {
	throw new Error('Default User ID is invalid');
}

// --- Logic Utama Worker ---

export default {
	/**
	 * Handler utama untuk setiap fetch request yang masuk ke worker.
	 * @param {import("@cloudflare/workers-types").Request} request - Request yang masuk.
	 * @param {object} env - Environment variables yang disediakan Cloudflare.
	 * @param {string} [env.UUID] - User ID (atau beberapa ID dipisahkan koma) dari environment.
	 * @param {string} [env.PROXY_IP] - Proxy IP (atau beberapa IP dipisahkan koma) dari environment.
	 * @param {string} [env.DNS_RESOLVER_URL] - URL DoH dari environment.
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx - Execution context.
	 * @returns {Promise<Response>} Response yang akan dikirim kembali ke client.
	 */
	async fetch(request, env, ctx) {
		try {
			// Prioritaskan konfigurasi dari Environment Variables
			userID = env.UUID || userID;
			proxyIP = env.PROXY_IP || proxyIP; // Jika env.PROXY_IP ada, gunakan itu, jika tidak gunakan nilai sebelumnya (acak atau default tunggal)
			dohURL = env.DNS_RESOLVER_URL || dohURL;

			// Ambil UUID pertama jika ada beberapa, untuk digunakan di path URL
			let firstUserID = userID.includes(',') ? userID.split(',')[0].trim() : userID;

			// Validasi lagi UUID dari env jika ada (opsional tapi bagus untuk keamanan)
			if (!userID.split(',').every(id => isValidUUID(id.trim()))) {
				console.error('Invalid UUID detected in environment or default configuration.');
				return new Response('Invalid UUID configuration', { status: 400 });
			}

			const upgradeHeader = request.headers.get('Upgrade');

			// Jika bukan request WebSocket upgrade
			if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
				const url = new URL(request.url);
				const host = request.headers.get('Host');

				switch (url.pathname) {
					case `/cf`: // Endpoint untuk info Cloudflare
						return new Response(JSON.stringify(request.cf, null, 4), {
							status: 200,
							headers: { "Content-Type": "application/json;charset=utf-8" },
						});

					case `/${firstUserID}`: // Endpoint untuk menampilkan konfigurasi VLESS dalam HTML
						if (!host) {
							return new Response("Host header is missing", { status: 400 });
						}
						const vlessConfig = getVlessConfig(userID, host, proxyIP);
						return new Response(vlessConfig, {
							status: 200,
							headers: { "Content-Type": "text/html; charset=utf-8" },
						});

					case `/sub/${firstUserID}`: // Endpoint untuk langganan (subscription) VLESS
						if (!host) {
							return new Response("Host header is missing", { status: 400 });
						}
						// const format = url.searchParams.get('format'); // Potensial untuk format lain (clash, etc.)
						const vlessSub = generateVlessSubscription(userID, host, proxyIP);
						return new Response(btoa(vlessSub), { // Encode Base64
							status: 200,
							headers: { "Content-Type": "text/plain;charset=utf-8" },
						});

					case `/bestip/${firstUserID}`: // Endpoint eksternal untuk IP terbaik (hati-hati dengan dependensi eksternal)
						// Catatan: Fungsionalitas ini bergantung pada layanan eksternal "sub.xf.free.hr".
						// Pastikan Anda mempercayai layanan ini dan sadar akan potensi downtime atau perubahan.
						const bestIpUrl = `https://sub.xf.free.hr/auto?host=${request.headers.get('Host')}&uuid=${userID}&path=/`;
						try {
							const bestSubResponse = await fetch(bestIpUrl, { headers: request.headers });
							// Periksa status response dari layanan eksternal
							if (!bestSubResponse.ok) {
								console.error(`Error fetching bestip from ${bestIpUrl}: ${bestSubResponse.status} ${bestSubResponse.statusText}`);
								// Mungkin kembalikan error atau fallback ke langganan biasa?
								// return new Response(`Failed to fetch best IP: ${bestSubResponse.statusText}`, { status: bestSubResponse.status });
								// Fallback: return subscription biasa
								const vlessSubFallback = generateVlessSubscription(userID, request.headers.get('Host') || '', proxyIP);
								return new Response(btoa(vlessSubFallback), { status: 200, headers: { "Content-Type": "text/plain;charset=utf-8", "X-Fallback-Used": "true" } });

							}
							return bestSubResponse;
						} catch (fetchError) {
							console.error(`Network error fetching bestip from ${bestIpUrl}:`, fetchError);
							// return new Response('Failed to fetch best IP due to network error', { status: 503 });
                             // Fallback: return subscription biasa
                            const vlessSubFallback = generateVlessSubscription(userID, request.headers.get('Host') || '', proxyIP);
                            return new Response(btoa(vlessSubFallback), { status: 200, headers: { "Content-Type": "text/plain;charset=utf-8", "X-Fallback-Used": "true" } });
						}


					default: // Semua path lain: Reverse Proxy ke Hostname Fallback
						// PERHATIAN: Fitur ini meneruskan request ke website eksternal.
						// Ini bisa digunakan untuk menyamarkan traffic, tapi juga memiliki risiko keamanan
						// dan mungkin melanggar ToS Cloudflare jika disalahgunakan.
						// Gunakan hanya jika Anda tahu apa yang Anda lakukan.
						const randomHostname = fallbackProxyHostnames[Math.floor(Math.random() * fallbackProxyHostnames.length)];
						const proxyUrl = `https://${randomHostname}${url.pathname}${url.search}`;

						// Salin headers asli, tapi modifikasi beberapa untuk menyembunyikan asal
						const newHeaders = new Headers(request.headers);
						newHeaders.set('cf-connecting-ip', '1.2.3.4'); // Contoh IP palsu
						newHeaders.set('x-forwarded-for', '1.2.3.4');  // Contoh IP palsu
						newHeaders.set('x-real-ip', '1.2.3.4');       // Contoh IP palsu
						newHeaders.set('referer', `https://www.google.com/search?q=${randomHostname}`); // Referer palsu
						newHeaders.set('Host', randomHostname); // Set Host header ke target

						let modifiedRequest = new Request(proxyUrl, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: 'manual', // Penting: Jangan ikuti redirect dari target secara otomatis
						});

						try {
							const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });

							// Blokir jika target mengembalikan redirect (301, 302, 307, 308)
							if ([301, 302, 307, 308].includes(proxyResponse.status)) {
								console.warn(`Blocked redirect attempt from ${randomHostname} to ${proxyResponse.headers.get('Location')}`);
								return new Response(`Redirects from ${randomHostname} are not allowed.`, {
									status: 403,
									statusText: 'Forbidden',
								});
							}

							// Kembalikan response dari target
                            // Kita perlu membuat Headers baru karena Headers dari Response tidak bisa dimodifikasi langsung di beberapa kasus
                            let responseHeaders = new Headers(proxyResponse.headers);
                            responseHeaders.set('Access-Control-Allow-Origin', '*'); // Contoh: Tambahkan CORS header jika perlu
                            responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');


							return new Response(proxyResponse.body, {
                                status: proxyResponse.status,
                                statusText: proxyResponse.statusText,
                                headers: responseHeaders
                            });
						} catch (proxyError) {
							console.error(`Error during fallback reverse proxy to ${proxyUrl}:`, proxyError);
							return new Response('Fallback proxy failed', { status: 502 });
						}
				}
			} else {
				// Handle permintaan WebSocket upgrade
				return await handleVlessOverWebSocket(request, userID, proxyIP, dohURL);
			}
		} catch (err) {
			console.error("Unhandled error in fetch handler:", err);
			/** @type {Error} */ let e = err;
			return new Response(e.toString(), { status: 500 });
		}
	},
};

/*
// Fungsi ini tampaknya tidak lengkap atau tidak digunakan secara aktif.
// Tujuannya mungkin untuk validasi subdomain berdasarkan hash tanggal/waktu.
// Dikomentari untuk saat ini. Jika ingin digunakan, perlu disempurnakan dan diintegrasikan.
async function uuid_validator(request) {
	const hostname = request.headers.get('Host');
	if (!hostname) return;
	const currentDate = new Date();

	const subdomain = hostname.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + subdomain
	const hashHex = await hashSHA256(subdomain);
	// subdomain string contains timestamps utc and uuid string TODO.
	console.log(`SHA256('${subdomain}') = ${hashHex}, Date: ${formattedDate}`);
}

async function hashSHA256(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
}
*/

/**
 * Menangani koneksi VLESS over WebSocket.
 * @param {import("@cloudflare/workers-types").Request} request - Request WebSocket upgrade.
 * @param {string} configuredUserID - UUID atau daftar UUID yang dikonfigurasi.
 * @param {string} configuredProxyIP - Proxy IP yang dikonfigurasi.
 * @param {string} configuredDohURL - URL DoH yang dikonfigurasi.
 * @returns {Promise<Response>} Response WebSocket (status 101) atau error.
 */
async function handleVlessOverWebSocket(request, configuredUserID, configuredProxyIP, configuredDohURL) {
	const webSocketPair = new WebSocketPair();
	const [client, server] = Object.values(webSocketPair);

	server.accept(); // Terima koneksi WebSocket dari sisi server worker

	let connectionState = {
		userID: configuredUserID,
		proxyIP: configuredProxyIP,
		dohURL: configuredDohURL,
		address: '', // Alamat tujuan yang diminta client
		port: 0,     // Port tujuan yang diminta client
		protocol: '', // Protokol (tcp/udp)
		remoteSocket: null, // Socket TCP ke tujuan
		udpStreamWriter: null, // Writer untuk stream UDP (via DoH)
		isDnsRequest: false,   // Apakah ini request UDP ke port 53
	};

	const log = (/** @type {string} */ info, /** @type {string | undefined | Error} */ event) => {
		const timestamp = new Date().toISOString();
		console.log(`[${timestamp} ${connectionState.address}:${connectionState.port || 'init'} ${connectionState.protocol || ''}] ${info}`, event || '');
	};

	try {
		const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
		const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader, log);

		await readableWebSocketStream.pipeTo(new WritableStream({
			async write(chunk, controller) {
				// Jika ini adalah request DNS yang sudah diidentifikasi, teruskan ke handler UDP
				if (connectionState.isDnsRequest && connectionState.udpStreamWriter) {
					return connectionState.udpStreamWriter(chunk);
				}

				// Jika socket remote TCP sudah dibuat, tulis langsung ke sana
				if (connectionState.remoteSocket) {
					try {
						const writer = connectionState.remoteSocket.writable.getWriter();
						await writer.write(chunk);
						writer.releaseLock();
						return;
					} catch (writeError) {
						log('Error writing to remote TCP socket:', writeError);
						controller.error(writeError); // Hentikan stream jika penulisan gagal
                        safeCloseWebSocket(server); // Tutup WebSocket juga
						return;
					}
				}

				// Jika belum ada socket remote, proses header VLESS dari chunk pertama
				const {
					hasError,
					errorReason,
					addressRemote = '',
					portRemote = 0,
					rawDataIndex = 0,
					vlessVersion = new Uint8Array([0, 0]),
					isUDP = false,
				} = processVlessHeader(chunk, connectionState.userID);

				if (hasError) {
					log('VLESS header processing error:', errorReason);
					controller.error(new Error(errorReason)); // Hentikan stream
                    safeCloseWebSocket(server); // Pastikan WS ditutup
					return; // Hentikan pemrosesan lebih lanjut
				}

				// Simpan detail koneksi yang diminta client
				connectionState.address = addressRemote;
				connectionState.port = portRemote;
				connectionState.protocol = isUDP ? 'udp' : 'tcp';

				log(`Request parsed: Target ${addressRemote}:${portRemote} (${connectionState.protocol})`);

				// Proses hanya UDP untuk port 53 (DNS)
				if (isUDP) {
					if (portRemote !== 53) {
						const errMsg = 'UDP proxy is only enabled for DNS requests on port 53.';
						log('Error:', errMsg);
						controller.error(new Error(errMsg));
                        safeCloseWebSocket(server);
						return;
					}
					connectionState.isDnsRequest = true;
				}

				// Header response VLESS (Version 0, No Error)
				const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
				const clientInitialData = chunk.slice(rawDataIndex);

				// --- Handling Koneksi Keluar (Outbound) ---
				if (connectionState.isDnsRequest) {
					// Handle UDP (DNS via DoH)
					try {
                        const { write } = await handleUdpOverDoH(server, vlessResponseHeader, connectionState.dohURL, log);
                        connectionState.udpStreamWriter = write; // Simpan fungsi write
                        connectionState.udpStreamWriter(clientInitialData); // Tulis data awal client
                        log('UDP (DoH) handler initialized.');
                    } catch (udpError) {
                        log('Error initializing UDP (DoH) handler:', udpError);
                        controller.error(udpError);
                        safeCloseWebSocket(server);
                    }
				} else {
					// Handle TCP
                    try {
                        await handleTcpOutbound(connectionState, clientInitialData, server, vlessResponseHeader, log);
                        log(`TCP connection handler initiated for ${connectionState.address}:${connectionState.port}.`);
                    } catch (tcpError) {
                        log(`Error initializing TCP outbound connection to ${connectionState.address}:${connectionState.port}:`, tcpError);
                        controller.error(tcpError);
                        safeCloseWebSocket(server);
                    }
				}
			},
			close() {
				log('Client WebSocket stream closed.');
                // Jika ada socket remote TCP, pastikan juga ditutup
                if (connectionState.remoteSocket) {
                    try {
                       connectionState.remoteSocket.close();
                    } catch (closeErr) {
                       log('Error closing remote TCP socket on client WS close:', closeErr);
                    }
                }
			},
			abort(reason) {
				log('Client WebSocket stream aborted:', reason);
                // Jika ada socket remote TCP, pastikan juga ditutup
                 if (connectionState.remoteSocket) {
                    try {
                       connectionState.remoteSocket.close();
                    } catch (closeErr) {
                       log('Error closing remote TCP socket on client WS abort:', closeErr);
                    }
                }
			},
		}), { preventCancel: false }); // preventCancel: false memungkinkan error untuk membatalkan pipe

	} catch (error) {
        // Tangkap error dari pipeTo atau stream creation
		log('Error in WebSocket handling pipeline:', error);
		safeCloseWebSocket(server); // Pastikan server ditutup jika terjadi error tak terduga
	}


	// Kembalikan response 101 Switching Protocols dengan sisi client dari WebSocketPair
	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * Menangani koneksi TCP keluar ke tujuan yang diminta.
 * Mencoba koneksi langsung, lalu fallback ke Proxy IP jika gagal atau tidak ada data.
 * @param {object} connectionState - Objek state koneksi saat ini.
 * @param {Uint8Array} rawClientData - Data awal dari client setelah header VLESS.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - WebSocket server untuk komunikasi dua arah.
 * @param {Uint8Array} vlessResponseHeader - Header VLESS untuk dikirim ke client jika koneksi berhasil.
 * @param {function} log - Fungsi logging.
 */
async function handleTcpOutbound(connectionState, rawClientData, webSocket, vlessResponseHeader, log) {
    let retried = false;

	/**
	 * Fungsi internal untuk membuat koneksi TCP dan menulis data awal.
     * @param {string} address - Alamat tujuan.
     * @param {number} port - Port tujuan.
     * @param {boolean} isRetry - Menandakan apakah ini upaya retry.
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} Socket yang berhasil terkoneksi.
	 */
	async function connectAndWrite(address, port, isRetry = false) {
        log(`Attempting ${isRetry ? 'retry ' : ''}TCP connection to ${address}:${port}...`);
		/** @type {import("@cloudflare/workers-types").Socket} */
        let tcpSocket;
        try {
             tcpSocket = connect({ hostname: address, port: port });
             connectionState.remoteSocket = tcpSocket; // Simpan socket ke state
             log(`Successfully initiated TCP connection to ${address}:${port}. Socket state: ${tcpSocket.readyState}`);
        } catch (connectionError) {
             log(`Failed to initiate TCP connection to ${address}:${port}:`, connectionError);
             throw connectionError; // Leparkan error agar bisa ditangani oleh pemanggil
        }


		try {
			const writer = tcpSocket.writable.getWriter();
            // Pastikan socket siap sebelum menulis (meskipun 'connect' biasanya async)
            // Cek state mungkin tidak selalu cukup di environment Worker, try-catch lebih aman.
            await writer.write(rawClientData);
            log(`Initial client data (${rawClientData.byteLength} bytes) written to ${address}:${port}.`);
            writer.releaseLock();
            return tcpSocket;

		} catch(writeError) {
            log(`Error writing initial data to ${address}:${port}:`, writeError);
             // Coba tutup socket jika gagal menulis data awal
             try { tcpSocket.close(); } catch(e) {}
             connectionState.remoteSocket = null; // Hapus dari state jika gagal
             throw writeError;
        }
	}

	/**
	 * Fungsi untuk menangani mekanisme retry menggunakan Proxy IP.
	 * @returns {Promise<void>}
	 */
	async function retryWithProxy() {
		if (retried || !connectionState.proxyIP || connectionState.proxyIP === connectionState.address) {
			log(`Retry condition not met. Retried: ${retried}, ProxyIP: ${connectionState.proxyIP}, Target: ${connectionState.address}`);
            safeCloseWebSocket(webSocket); // Tidak bisa retry, tutup koneksi
			throw new Error("Cannot retry connection.");
		}

        retried = true; // Tandai bahwa retry sudah dilakukan
		log(`Retrying connection using Proxy IP: ${connectionState.proxyIP}:${connectionState.port}...`);
		try {
			// Koneksi menggunakan Proxy IP
            const tcpSocket = await connectAndWrite(connectionState.proxyIP, connectionState.port, true);
            log(`Retry connection to proxy ${connectionState.proxyIP}:${connectionState.port} successful.`);
            pipeRemoteSocketToWebSocket(tcpSocket, webSocket, vlessResponseHeader, null, log); // Pipe tanpa opsi retry lagi
		} catch (retryError) {
			log(`Retry connection using Proxy IP ${connectionState.proxyIP} failed:`, retryError);
            safeCloseWebSocket(webSocket); // Gagal retry, tutup koneksi
            throw retryError; // Leparkan error agar pemanggil tahu
		}
	}

	// --- Coba Koneksi Awal ---
	try {
        const tcpSocket = await connectAndWrite(connectionState.address, connectionState.port, false);
         log(`Initial connection to ${connectionState.address}:${connectionState.port} seems successful. Piping data...`);
        pipeRemoteSocketToWebSocket(tcpSocket, webSocket, vlessResponseHeader, retryWithProxy, log); // Pipe dengan opsi retry
	} catch (initialError) {
        // Jika koneksi awal gagal total, coba langsung retry (jika memungkinkan)
		log(`Initial connection to ${connectionState.address}:${connectionState.port} failed. Error: ${initialError}. Attempting retry with proxy...`);
		try {
            await retryWithProxy();
        } catch (retryFailedError) {
             log(`Both initial connection and retry failed.`);
            // Error sudah di-log di dalam retryWithProxy, tidak perlu throw lagi
             // Pastikan WebSocket ditutup jika semua upaya gagal
            safeCloseWebSocket(webSocket);
        }
	}
}


/**
 * Mem-pipe data dari socket remote TCP ke WebSocket client.
 * Mengimplementasikan mekanisme deteksi 'no incoming data' untuk memicu retry.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket - Socket TCP ke tujuan.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - WebSocket server.
 * @param {Uint8Array | null} vlessResponseHeader - Header VLESS yang akan dikirim pada chunk data pertama.
 * @param {(() => Promise<void>) | null} retryCallback - Fungsi callback untuk dipanggil jika retry diperlukan.
 * @param {(info: string, event?: any) => void} log - Fungsi logging.
 */
async function pipeRemoteSocketToWebSocket(remoteSocket, webSocket, vlessResponseHeader, retryCallback, log) {
	let hasIncomingData = false;
    let responseHeaderSent = false; // Untuk memastikan header hanya dikirim sekali
    const remoteAddress = `${remoteSocket.remoteAddress}:${remoteSocket.remotePort}`; // Dapatkan alamat remote untuk logging

	try {
        await remoteSocket.readable.pipeTo(
            new WritableStream({
                start() {
                    log(`[${remoteAddress}] Started piping remote TCP -> WebSocket.`);
                },
                /**
                 * Menulis chunk data dari socket remote ke WebSocket.
                 * @param {Uint8Array} chunk - Data chunk.
                 * @param {WritableStreamDefaultController} controller - Kontroler stream.
                 */
                async write(chunk, controller) {
                    hasIncomingData = true; // Tandai bahwa data telah diterima

                    // Pastikan WebSocket masih terbuka sebelum mengirim
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                         log(`[${remoteAddress}] WebSocket is not open (state: ${webSocket.readyState}). Stopping pipe.`);
                        controller.error(new Error('WebSocket is not open'));
                        // Kita ingin menghentikan pipe, tapi mungkin tidak perlu close socket remote secara eksplisit di sini, biarkan ditutup oleh sisi lain atau saat cleanup
                         // Coba close socket remote
                         // try { remoteSocket.close(); } catch (e) { log(`[${remoteAddress}] Error closing remote socket on WS write failure:`, e); }
                        return; // Hentikan pemrosesan chunk ini
                    }

                    try {
                         // Kirim header VLESS bersamaan dengan chunk data pertama
                        if (vlessResponseHeader && !responseHeaderSent) {
                            const dataToSend = new Uint8Array(vlessResponseHeader.byteLength + chunk.byteLength);
                            dataToSend.set(vlessResponseHeader, 0);
                            dataToSend.set(chunk, vlessResponseHeader.byteLength);
                             webSocket.send(dataToSend.buffer); // Kirim ArrayBuffer
                            responseHeaderSent = true; // Tandai header sudah dikirim
                             log(`[${remoteAddress}] Sent VLESS response header + ${chunk.byteLength} bytes data chunk to WebSocket.`);
                        } else {
                             webSocket.send(chunk); // Kirim chunk data biasa (sudah dalam bentuk yang bisa dikirim, biasanya Uint8Array)
                            // log(`[${remoteAddress}] Sent ${chunk.byteLength} bytes data chunk to WebSocket.`); // Komentar untuk mengurangi log spam
                        }
                    } catch (wsSendError) {
                        log(`[${remoteAddress}] Error sending data to WebSocket:`, wsSendError);
                        controller.error(wsSendError); // Beri tahu stream ada error
                        // Tutup juga remote socket jika WebSocket error
                        try { remoteSocket.close(); } catch (e) { log(`[${remoteAddress}] Error closing remote socket on WS send error:`, e); }

                    }
                },
                close() {
                     log(`[${remoteAddress}] Remote TCP socket readable stream closed. Has incoming data: ${hasIncomingData}. WebSocket state: ${webSocket.readyState}.`);
                    // Jangan tutup WebSocket dari sini secara default.
                    // Biasanya, client yang akan menutup WebSocket jika sisi remote menutup koneksi TCP.
                    // safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                     log(`[${remoteAddress}] Remote TCP socket readable stream aborted:`, reason);
                    // Jika stream remote dibatalkan (misal karena error), kita juga harus menutup WebSocket.
                    safeCloseWebSocket(webSocket);
                    // Coba tutup juga remote socket
                    try { remoteSocket.close(); } catch (e) { log(`[${remoteAddress}] Error closing remote socket on stream abort:`, e); }
                },
            }),
            { signal: remoteSocket.closed } // Gunakan 'closed' promise sebagai sinyal pembatalan
        );
	} catch (error) {
		// Tangani error yang mungkin terjadi selama proses pipeTo (misalnya jika socket ditutup tiba-tiba)
        // Abaikan error AbortError karena itu diharapkan jika socket ditutup
        if (error.name === 'AbortError') {
             log(`[${remoteAddress}] Pipe remote TCP -> WebSocket aborted (expected on socket close).`);
        } else {
            console.error(`[${remoteAddress}] Error piping remote TCP -> WebSocket:`, error);
             safeCloseWebSocket(webSocket); // Tutup WS jika terjadi error tak terduga
            try { remoteSocket.close(); } catch (e) { log(`[${remoteAddress}] Error closing remote socket on pipe error:`, e); }
        }

	}

    // Cek setelah pipe selesai atau gagal: Jika tidak ada data masuk DAN ada callback retry, panggil retry.
	// Ini menangani kasus di mana koneksi TCP berhasil tapi remote tidak mengirim data (mungkin firewall, dll).
	if (!hasIncomingData && retryCallback) {
		log(`[${remoteAddress}] No data received from remote TCP socket. Triggering retry...`);
		try {
            await retryCallback();
        } catch (retryError) {
             log(`[${remoteAddress}] Retry failed after no data received. Error: ${retryError}`);
            // Jika retry juga gagal, pastikan WebSocket ditutup.
             safeCloseWebSocket(webSocket);
        }
	} else if (!hasIncomingData) {
        log(`[${remoteAddress}] No data received from remote TCP socket, and no retry mechanism available.`);
        // Jika tidak ada data dan tidak bisa retry, tutup koneksi WebSocket.
        safeCloseWebSocket(webSocket);
        // Coba tutup remote socket juga
         try { remoteSocket.close(); } catch (e) { log(`[${remoteAddress}] Error closing remote socket after no data received (no retry):`, e); }
    }
}

/**
 * Membuat ReadableStream dari pesan yang diterima WebSocket server.
 * Juga menangani data awal dari header `sec-websocket-protocol`.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer - Instance WebSocket dari sisi server.
 * @param {string} earlyDataHeader - Isi header 'sec-websocket-protocol' (base64 encoded early data).
 * @param {function} log - Fungsi logging.
 * @returns {ReadableStream<Uint8Array>} Stream yang bisa dibaca.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let controllerRef = null; // Referensi ke controller stream

	// Event listener untuk pesan masuk
	const messageListener = (event) => {
        // event.data bisa berupa string, ArrayBuffer, Blob. Kita asumsikan ArrayBuffer/Blob untuk VLESS.
		let data = event.data;
        if (typeof data === 'string') {
             log("Warning: Received string data from WebSocket, expected binary. Encoding to Uint8Array.");
             data = new TextEncoder().encode(data);
         } else if (data instanceof Blob) {
             log("Info: Received Blob data, converting to ArrayBuffer.");
             // Jika data adalah Blob, kita perlu membacanya sebagai ArrayBuffer
             // Perhatikan ini async, mungkin perlu penanganan khusus jika urutan penting
             data.arrayBuffer().then(arrayBuffer => {
                 if (controllerRef && controllerRef.desiredSize > 0) {
                    controllerRef.enqueue(new Uint8Array(arrayBuffer));
                } else if (!controllerRef) {
                    log("Error: Stream controller not available when Blob processing finished.");
                } else {
                    log("Warning: Stream buffer full, dropping Blob data.");
                }
             }).catch(err => {
                 log("Error converting Blob to ArrayBuffer:", err);
                 if (controllerRef) controllerRef.error(err);
             });
             return; // Jangan enqueue langsung jika Blob, tunggu konversi selesai
         } else if (!(data instanceof ArrayBuffer)) {
            log(`Error: Received unexpected data type from WebSocket: ${typeof data}`);
            if (controllerRef) controllerRef.error(new TypeError("Unexpected WebSocket data type"));
            return;
         }

         // Enqueue jika data adalah ArrayBuffer (atau sudah dikonversi dari string)
         if (controllerRef && controllerRef.desiredSize > 0) { // Cek backpressure
              controllerRef.enqueue(new Uint8Array(data));
         } else if (!controllerRef) {
             log("Error: Stream controller not available.");
         } else {
              log(`Warning: WebSocket stream buffer full (desiredSize: ${controllerRef.desiredSize}). Backpressure applied.`);
              // TODO: Implementasikan mekanisme backpressure yang lebih baik jika diperlukan
              // Misalnya, stop menerima pesan dari WebSocket untuk sementara?
         }

	};

    // Event listener untuk penutupan WebSocket
	const closeListener = () => {
		log('WebSocket connection closed by remote.');
		if (controllerRef) {
             try {
                 controllerRef.close(); // Tutup stream jika WebSocket ditutup
             } catch (e) {
                 if (e.message.includes("Cannot close a readable stream controller that is closing")) {
                    // Abaikan error ini, bisa terjadi jika close sudah dipanggil sebelumnya
                 } else {
                    log("Error closing stream on WebSocket close:", e);
                 }
             }
         }
		// Hapus listener untuk mencegah memory leak
		webSocketServer.removeEventListener('message', messageListener);
		webSocketServer.removeEventListener('close', closeListener);
		webSocketServer.removeEventListener('error', errorListener);
	};

    // Event listener untuk error WebSocket
	const errorListener = (err) => {
		log('WebSocket error occurred:', err);
		if (controllerRef) {
			controllerRef.error(err); // Sebarkan error ke stream
		}
		// Hapus listener
        webSocketServer.removeEventListener('message', messageListener);
        webSocketServer.removeEventListener('close', closeListener);
        webSocketServer.removeEventListener('error', errorListener);
	};

	return new ReadableStream({
		start(controller) {
			controllerRef = controller; // Simpan referensi controller

			// Pasang event listener
			webSocketServer.addEventListener('message', messageListener);
			webSocketServer.addEventListener('close', closeListener);
			webSocketServer.addEventListener('error', errorListener);

			// Proses early data jika ada
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				log("Error decoding early data from sec-websocket-protocol header:", error);
				controller.error(error);
			} else if (earlyData && earlyData.byteLength > 0) {
				log(`Processing ${earlyData.byteLength} bytes of early data.`);
				controller.enqueue(new Uint8Array(earlyData));
			}
		},

		// pull(controller) {
			// Tarik data jika diperlukan (biasanya tidak untuk WebSocket push source)
			// Implementasi backpressure bisa ditambahkan di sini jika listener 'message' mendeteksinya
		// },

		cancel(reason) {
			log(`WebSocket readable stream cancelled. Reason:`, reason);
            // Hapus listener saat stream dibatalkan
            webSocketServer.removeEventListener('message', messageListener);
            webSocketServer.removeEventListener('close', closeListener);
            webSocketServer.removeEventListener('error', errorListener);
            // Tutup WebSocket jika stream dibatalkan oleh konsumen hilir
			safeCloseWebSocket(webSocketServer);
		}
	});
}

// Konstanta state WebSocket untuk kejelasan
const WS_READY_STATE_CONNECTING = 0;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const WS_READY_STATE_CLOSED = 3;

/**
 * Menutup WebSocket dengan aman, menangani kemungkinan error jika sudah ditutup.
 * @param {import("@cloudflare/workers-types").WebSocket} socket - WebSocket yang akan ditutup.
 * @param {number} [code] - Kode penutupan WebSocket (opsional).
 * @param {string} [reason] - Alasan penutupan (opsional).
 */
function safeCloseWebSocket(socket, code, reason) {
    try {
        switch (socket.readyState) {
            case WS_READY_STATE_OPEN:
            case WS_READY_STATE_CLOSING: // Boleh coba tutup lagi jika sedang closing
                socket.close(code, reason);
                break;
            case WS_READY_STATE_CONNECTING:
            case WS_READY_STATE_CLOSED:
                // Tidak perlu melakukan apa-apa jika sedang konek atau sudah tertutup
                break;
        }
    } catch (error) {
        // Terkadang error bisa terjadi jika socket ditutup secara tidak normal
        // console.error("Error closing WebSocket (might be acceptable):", error);
    }
}


/**
 * Memproses header VLESS dari data biner yang diterima.
 * Referensi: https://xtls.github.io/development/protocols/vless.html
 * @param {ArrayBuffer} vlessBuffer - Buffer yang berisi data VLESS (minimal header).
 * @param {string} configuredUserID - UUID atau daftar UUID yang valid, dipisahkan koma.
 * @returns {{
 *  hasError: boolean,
 *  errorReason?: string,
 *  addressRemote?: string,
 *  addressType?: number, // 1: IPv4, 2: Domain, 3: IPv6
 *  portRemote?: number,
 *  rawDataIndex?: number, // Index awal data payload setelah header
 *  vlessVersion?: Uint8Array, // Versi VLESS yang terdeteksi
 *  isUDP?: boolean // Apakah command UDP (0x02) diminta
 * }} Hasil pemrosesan header.
 */
function processVlessHeader(vlessBuffer, configuredUserID) {
	if (vlessBuffer.byteLength < 24) { // Minimal: 1(ver)+16(uuid)+1(addlen)+1(cmd)+2(port)+1(atype)+1(addr min)
		return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short (< 24 bytes)' };
	}
    const dataView = new DataView(vlessBuffer);
    const version = new Uint8Array(vlessBuffer.slice(0, 1)); // Ambil versi (byte pertama)

	if (version[0] !== 0) {
		// Saat ini hanya VLESS versi 0 yang didukung secara luas
        // Mungkin di masa depan perlu menangani versi lain.
		return { hasError: true, errorReason: `Unsupported VLESS version: ${version[0]}. Only version 0 is supported.` };
	}

	// Ekstrak UUID (16 bytes setelah versi)
	const uuidBytes = new Uint8Array(vlessBuffer.slice(1, 17));
	const receivedUUID = uuidBytesToString(uuidBytes);
	if (!receivedUUID) {
		return { hasError: true, errorReason: 'Failed to parse received UUID.' };
	}

    // Validasi User ID
	const validUserIDs = configuredUserID.split(',').map(id => id.trim());
	if (!validUserIDs.includes(receivedUUID)) {
		console.warn(`Invalid user attempt: ${receivedUUID}. Allowed: ${configuredUserID}`);
		return { hasError: true, errorReason: `Invalid user: ${receivedUUID}` };
	}

    // Panjang Addons (saat ini diabaikan)
	const addonLength = dataView.getUint8(17);
    const commandIndex = 18 + addonLength; // Index byte command setelah addons

    if (vlessBuffer.byteLength <= commandIndex) {
		return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for command.' };
	}

    // Command (1 byte): 0x01=TCP, 0x02=UDP, 0x03=MUX (tidak didukung)
	const command = dataView.getUint8(commandIndex);
	let isUDP = false;
	if (command === 0x01) { // TCP
		isUDP = false;
	} else if (command === 0x02) { // UDP
		isUDP = true;
	} else {
		return { hasError: true, errorReason: `Unsupported command: ${command}. Only TCP (1) and UDP (2) are supported.` };
	}

    // Port (2 bytes, big-endian) setelah command
    const portIndex = commandIndex + 1;
     if (vlessBuffer.byteLength < portIndex + 2) {
		return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for port.' };
	}
	const portRemote = dataView.getUint16(portIndex, false); // false = big-endian

    // Address Type (1 byte) setelah port
	const addressTypeIndex = portIndex + 2;
     if (vlessBuffer.byteLength <= addressTypeIndex) {
		return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for address type.' };
	}
	const addressType = dataView.getUint8(addressTypeIndex);

	let addressRemote = '';
	let addressLength = 0;
	let addressValueIndex = addressTypeIndex + 1; // Index awal nilai alamat

	switch (addressType) {
		case 0x01: // IPv4 (4 bytes)
			addressLength = 4;
            if (vlessBuffer.byteLength < addressValueIndex + addressLength) {
                return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for IPv4 address.' };
            }
			addressRemote = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 0x02: // Domain Name (1 byte length + N bytes name)
            if (vlessBuffer.byteLength <= addressValueIndex) { // Minimal perlu byte panjang domain
                return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for domain length.' };
            }
			addressLength = dataView.getUint8(addressValueIndex); // Panjang domain
			addressValueIndex += 1; // Pindah ke awal domain name
            if (vlessBuffer.byteLength < addressValueIndex + addressLength) {
                 return { hasError: true, errorReason: `Invalid VLESS header: buffer too short for domain name (expected ${addressLength} bytes).` };
            }
            try {
                 addressRemote = new TextDecoder('utf-8', { fatal: true }) // Gunakan fatal:true untuk menangkap error encoding
                                 .decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            } catch(decodeError) {
                 return { hasError: true, errorReason: `Failed to decode domain name: ${decodeError}`};
            }

			break;
		case 0x03: // IPv6 (16 bytes)
			addressLength = 16;
             if (vlessBuffer.byteLength < addressValueIndex + addressLength) {
                 return { hasError: true, errorReason: 'Invalid VLESS header: buffer too short for IPv6 address.' };
            }
			const ipv6Bytes = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            // Format ke string hextet
            const ipv6Segments = [];
            for (let i = 0; i < 16; i += 2) {
                ipv6Segments.push(((ipv6Bytes[i] << 8) | ipv6Bytes[i + 1]).toString(16));
            }
			addressRemote = ipv6Segments.join(':');
            // Pertimbangkan normalisasi/kompresi IPv6 jika perlu, tapi biasanya tidak untuk tujuan koneksi
			break;
		default:
			return { hasError: true, errorReason: `Invalid address type: ${addressType}. Expected 1 (IPv4), 2 (Domain), or 3 (IPv6).` };
	}

	// Index awal payload data client (setelah alamat)
	const rawDataIndex = addressValueIndex + addressLength;

    // Lakukan pemeriksaan akhir panjang buffer vs index payload
    // (Sebenarnya sudah tersirat oleh pemeriksaan di setiap langkah, tapi ini eksplisit)
     if (vlessBuffer.byteLength < rawDataIndex) {
          return { hasError: true, errorReason: 'Invalid VLESS header: Calculated raw data index exceeds buffer length.' };
     }


	return {
		hasError: false,
		addressRemote,
		addressType,
		portRemote,
		rawDataIndex,
		vlessVersion: version,
		isUDP,
	};
}


// --- Helper Functions ---

/**
 * Mengubah buffer byte UUID menjadi string UUID standar.
 * @param {Uint8Array} buffer - Buffer 16-byte UUID.
 * @returns {string | null} String UUID atau null jika buffer tidak valid.
 */
function uuidBytesToString(buffer) {
    if (!buffer || buffer.byteLength !== 16) {
		return null; // Buffer harus 16 byte
	}
	const hex = Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
	// Format: 8-4-4-4-12
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Mengonversi string base64 (standar atau URL-safe) ke ArrayBuffer.
 * @param {string} base64Str - String base64.
 * @returns {{ earlyData: ArrayBuffer | null, error: Error | null }} Objek hasil konversi.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// Normalisasi base64 URL-safe ke standar
		let normalizedBase64 = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        // Tambahkan padding jika perlu (browser modern `atob` mungkin tidak memerlukannya)
        // const padding = normalizedBase64.length % 4;
        // if (padding) {
        //     normalizedBase64 += '='.repeat(4 - padding);
        // }

		const binaryString = atob(normalizedBase64); // Dekode base64 ke string biner
		const len = binaryString.length;
		const bytes = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			bytes[i] = binaryString.charCodeAt(i); // Konversi karakter biner ke byte
		}
		return { earlyData: bytes.buffer, error: null };
	} catch (error) {
        console.error("Base64 decoding error:", error); // Log error untuk debugging
		return { earlyData: null, error: new Error(`Failed to decode base64 string: ${error.message}`) };
	}
}

/**
 * Memvalidasi apakah string adalah format UUID v4 yang valid.
 * Regex ini cukup ketat untuk format standar.
 * @param {string} uuid - String yang akan divalidasi.
 * @returns {boolean} True jika valid, false jika tidak.
 */
function isValidUUID(uuid) {
    if (!uuid || typeof uuid !== 'string') {
        return false;
    }
    // Regex for UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // where y is 8, 9, A, or B.
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

// --- Fungsi untuk Menghasilkan Konfigurasi & Langganan ---
const base64EncodedVless = btoa('vless'); // "dmxlc3M="
const base64EncodedAt = btoa('@');     // "QA=="
const base64EncodedEd = btoa('EDtunnel'); // Opsional, untuk penanda di nama node

/**
 * Menghasilkan representasi HTML dari konfigurasi VLESS.
 * @param {string} userIDs - Satu atau beberapa UUID (dipisahkan koma).
 * @param {string} hostName - Hostname worker (dari header Host).
 * @param {string} proxyIPValue - Proxy IP yang akan ditampilkan di konfigurasi alternatif.
 * @returns {string} String HTML.
 */
function getVlessConfig(userIDs, hostName, proxyIPValue) {
	const userIDArray = userIDs.split(',').map(id => id.trim());
	const firstUserID = userIDArray[0];

    // Komponen URL VLESS yang umum
    const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048`; // Path encode dari "/?ed=2048"
    const fragmentBase = `#${hostName}`;

	const configs = userIDArray.map((userID) => {
		const vlessMain = `${base64EncodedVless}://${userID}${base64EncodedAt}${hostName}${commonUrlPart}${fragmentBase}`;
		const vlessProxy = `${base64EncodedVless}://${userID}${base64EncodedAt}${proxyIPValue}${commonUrlPart}${fragmentBase}-${proxyIPValue}-${base64EncodedEd}`;

		return `
        <h2>UUID: ${userID}</h2>
        <button onclick='copyToClipboard("${userID}")'><i class="fa fa-clipboard"></i> Salin UUID</button>
        <hr>
        <h4>Konfigurasi Utama (Alamat Host):</h4>
        <pre>${vlessMain}</pre>
        <button onclick='copyToClipboard("${vlessMain}")'><i class="fa fa-clipboard"></i> Salin Link Utama</button>
        <h4>Konfigurasi Alternatif (Alamat Proxy IP):</h4>
        <p>(Gunakan jika koneksi ke alamat host bermasalah. Alamat IP mungkin berubah.)</p>
        <pre>${vlessProxy}</pre>
        <button onclick='copyToClipboard("${vlessProxy}")'><i class="fa fa-clipboard"></i> Salin Link Alternatif</button>
        <br><br>
        `;
	}).join('');

	const subscribeURL = `https://${hostName}/sub/${firstUserID}`;
    const subscribeURLClash = `https://${hostName}/sub/${firstUserID}?format=clash`; // Contoh parameter untuk Clash
    const subscribeBestIP = `https://${hostName}/bestip/${firstUserID}`;

	// Link Clash via API converter (contoh)
    const clashConverterURL = `https://api.v1.mk/sub?target=clash&url=${encodeURIComponent(subscribeURLClash)}&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;

    // Bagian header HTML
	const header = `
      <div style="text-align: center;">
        <p><img src='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' alt='EDtunnel Logo' style='max-width: 200px; margin-bottom: 10px;'></p>
        <b style='font-size: 1.1em;'>Selamat Datang! Ini adalah halaman konfigurasi VLESS.</b><br>
        <p>Proyek Sumber Terbuka: <a href='https://github.com/3Kmfi6HP/EDtunnel' target='_blank'>EDtunnel di GitHub</a></p>
        <iframe src='https://ghbtns.com/github-btn.html?user=3Kmfi6HP&repo=EDtunnel&type=star&count=true&size=large' frameborder='0' scrolling='0' width='170' height='30' title='GitHub Stars'></iframe>
        <hr style="margin: 20px 0;">
        <h3>Link Langganan (Subscription):</h3>
        <p><a href='${subscribeURL}' target='_blank'>Link Langganan VLESS Biasa</a></p>
        <p>(Klik kanan dan salin link jika perlu)</p>
        <br>
        <p><strong>Integrasi Aplikasi Client:</strong></p>
        <p>
          <a href='clash://install-config?url=${encodeURIComponent(subscribeURLClash)}' target='_blank'>Import ke Clash (Format URL)</a> |
          <a href='${clashConverterURL}' target='_blank'>Import ke Clash (via Converter)</a> |
          <a href='v2rayng://install-config?url=${encodeURIComponent(subscribeBestIP)}' target='_blank'>Import ke V2RayNG (Otomatis Best IP)</a>
        </p>
         <p>
          <a href='sing-box://import-remote-profile?url=${encodeURIComponent(subscribeBestIP)}' target='_blank'>Import ke Sing-Box (Otomatis Best IP)</a> |
          <a href='sn://subscription?url=${encodeURIComponent(subscribeBestIP)}' target='_blank'>Import ke Nekoray/Box (Otomatis Best IP)</a>
        </p>
        <p>(Tombol Otomatis Best IP memerlukan layanan eksternal sub.xf.free.hr)</p>
         <hr style="margin: 20px 0;">
      </div>`;

	// Head HTML dengan CSS sederhana dan FontAwesome
	const htmlHead = `
    <head>
      <title>EDtunnel: Konfigurasi VLESS</title>
      <meta charset="UTF-8">
      <meta name='description' content='Halaman Konfigurasi VLESS dari EDtunnel.'>
      <meta name='keywords' content='VLESS, Cloudflare, EDtunnel, Worker, Proxy'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <meta property='og:title' content='EDtunnel - Konfigurasi VLESS' />
      <meta property='og:description' content='Hasilkan konfigurasi VLESS menggunakan Cloudflare Worker.' />
      <meta property='og:url' content='https://${hostName}/' />
      <meta property='og:site_name' content='EDtunnel Config' />
      <meta property='og:image' content='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' />
	  <meta property='og:type' content='website' />
	  <meta name='twitter:card' content='summary_large_image' />
      <meta name='twitter:title' content='EDtunnel - Konfigurasi VLESS' />
      <meta name='twitter:description' content='Hasilkan konfigurasi VLESS menggunakan Cloudflare Worker.' />
      <meta name='twitter:url' content='https://${hostName}/' />
	  <meta name='twitter:image' content='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' />

      <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; background-color: #f4f4f4; color: #333; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        pre { background-color: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; white-space: pre-wrap; word-wrap: break-word; font-family: "Courier New", Courier, monospace; }
        h2, h3, h4 { color: #555; border-bottom: 1px solid #eee; padding-bottom: 5px; margin-top: 25px;}
        hr { border: 0; height: 1px; background: #ddd; }
        button { background-color: #007bff; color: white; border: none; padding: 8px 15px; text-align: center; text-decoration: none; display: inline-block; font-size: 14px; cursor: pointer; border-radius: 4px; margin: 5px 2px; }
        button:hover { background-color: #0056b3; }
        button i { margin-right: 5px; }
        /* Dark mode */
        @media (prefers-color-scheme: dark) {
          body { background-color: #282a36; color: #f8f8f2; }
          a { color: #bd93f9; }
          pre { background-color: #44475a; border-color: #6272a4; color: #f8f8f2;}
          h2, h3, h4 { color: #f8f8f2; border-bottom-color: #44475a; }
          hr { background: #44475a; }
          button { background-color: #6272a4; }
          button:hover { background-color: #50fa7b; }
        }
      </style>
    </head>`;

	// Gabungkan semua bagian menjadi HTML lengkap
	return `
    <!DOCTYPE html>
    <html>
    ${htmlHead}
    <body>
      ${header}
      <div style="padding-top: 20px;">
        ${configs}
      </div>
      <script>
        function copyToClipboard(text) {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
              alert("Teks berhasil disalin ke clipboard!");
            }).catch(err => {
              console.error("Gagal menyalin ke clipboard:", err);
              // Fallback jika API tidak didukung atau gagal
              fallbackCopyTextToClipboard(text);
            });
          } else {
            // Fallback untuk browser lama atau environment tidak aman
            fallbackCopyTextToClipboard(text);
          }
        }
        function fallbackCopyTextToClipboard(text) {
           const textArea = document.createElement("textarea");
           textArea.value = text;
           textArea.style.position = "fixed"; // Prevent scrolling to bottom of page in MS Edge.
           textArea.style.left = "-9999px";
           document.body.appendChild(textArea);
           textArea.focus();
           textArea.select();
           try {
              const successful = document.execCommand('copy');
              const msg = successful ? 'berhasil' : 'gagal';
              alert('Fallback: Teks ' + msg + ' disalin ke clipboard.');
           } catch (err) {
              console.error('Fallback: Gagal menyalin', err);
              alert('Fallback: Gagal menyalin teks.');
           }
           document.body.removeChild(textArea);
        }
      </script>
    </body>
    </html>`;
}

/**
 * Menghasilkan konten subscription VLESS (satu URL VLESS per baris).
 * @param {string} userIDs - Satu atau beberapa UUID (dipisahkan koma).
 * @param {string} hostName - Hostname worker.
 * @param {string} proxyIPValue - Proxy IP alternatif.
 * @returns {string} String berisi VLESS URLs, dipisahkan newline.
 */
function generateVlessSubscription(userIDs, hostName, proxyIPValue) {
	const userIDArray = userIDs.split(',').map(id => id.trim());
	let output = [];

    // Filter proxyIPValue jika itu adalah array string dari environment (ambil yang pertama sebagai contoh)
    let effectiveProxyIP = Array.isArray(proxyIPValue) ? proxyIPValue[0] : proxyIPValue;

	// Common parts
    const commonTlsPart = `?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`; // TLS via WSS
    const commonHttpPart = `?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`; // Non-TLS via WS

	userIDArray.forEach((userID) => {
		// --- HTTPS/WSS Nodes ---
        httpsPorts.forEach(port => {
            // Node utama (via Hostname)
             let nodeNameMain = `${hostName}_WSS_${port}`;
            output.push(`${base64EncodedVless}://${userID}${base64EncodedAt}${hostName}:${port}${commonTlsPart}${encodeURIComponent(nodeNameMain)}`);

             // Node alternatif (via Proxy IP) - hanya jika proxy IP berbeda dari hostname
             if (effectiveProxyIP && effectiveProxyIP !== hostName) {
                 let nodeNameProxy = `${hostName}_WSS_${port}_${effectiveProxyIP}`;
                 output.push(`${base64EncodedVless}://${userID}${base64EncodedAt}${effectiveProxyIP}:${port}${commonTlsPart}${encodeURIComponent(nodeNameProxy)}`);
            }

        });

        // --- HTTP/WS Nodes ---
         // Hindari menambahkan node HTTP jika hostname adalah .dev atau domain khusus CF lainnya yang hanya HTTPS
        if (!hostName.endsWith('pages.dev') && !hostName.endsWith('workers.dev')) { // Contoh pengecualian
            httpPorts.forEach(port => {
                 // Node utama (via Hostname)
                 let nodeNameMain = `${hostName}_WS_${port}`;
                output.push(`${base64EncodedVless}://${userID}${base64EncodedAt}${hostName}:${port}${commonHttpPart}${encodeURIComponent(nodeNameMain)}`);

                 // Node alternatif (via Proxy IP) - hanya jika proxy IP berbeda dari hostname
                 if (effectiveProxyIP && effectiveProxyIP !== hostName) {
                    let nodeNameProxy = `${hostName}_WS_${port}_${effectiveProxyIP}`;
                    output.push(`${base64EncodedVless}://${userID}${base64EncodedAt}${effectiveProxyIP}:${port}${commonHttpPart}${encodeURIComponent(nodeNameProxy)}`);
                }
            });
        }

	});

	return output.join('\n');
}

// --- UDP over DoH Handler ---
/**
 * Menangani lalu lintas UDP keluar (khusus DNS port 53) dengan meneruskannya melalui DoH.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - WebSocket server.
 * @param {ArrayBuffer} vlessResponseHeader - Header respons VLESS awal.
 * @param {string} dohURL - URL resolver DoH.
 * @param {(info: string, event?: any) => void} log - Fungsi logging.
 * @returns {Promise<{ write: (chunk: Uint8Array) => void }>} Objek dengan fungsi 'write' untuk menerima chunk UDP dari WebSocket.
 */
async function handleUdpOverDoH(webSocket, vlessResponseHeader, dohURL, log) {
	let vlessHeaderSent = false;
    let accumulatedData = new Uint8Array(0); // Buffer untuk data UDP parsial

	// Transform stream untuk memproses data UDP dari WebSocket
	// Data UDP di VLESS memiliki prefix panjang 2 byte
	const transformStream = new TransformStream({
		transform(chunk, controller) {
			// Gabungkan data baru dengan sisa data sebelumnya
             const newData = new Uint8Array(accumulatedData.length + chunk.length);
             newData.set(accumulatedData, 0);
             newData.set(chunk, accumulatedData.length);
             accumulatedData = newData;

			// Proses selama masih ada cukup data untuk header panjang + payload
            while (accumulatedData.length >= 2) {
                 const dataView = new DataView(accumulatedData.buffer, accumulatedData.byteOffset, accumulatedData.byteLength);
                 const expectedLength = dataView.getUint16(0, false); // Panjang payload UDP (Big Endian)
                 const totalPacketLength = 2 + expectedLength; // Panjang total = header 2 byte + payload

                // Jika data yang terkumpul cukup untuk satu paket penuh
                if (accumulatedData.length >= totalPacketLength) {
                    const udpPayload = accumulatedData.slice(2, totalPacketLength);
                    controller.enqueue(udpPayload); // Kirim payload UDP ke hilir
                     log(`UDP(DoH): Enqueued DNS query payload (${udpPayload.byteLength} bytes).`);
                    // Buang paket yang sudah diproses dari buffer akumulasi
                    accumulatedData = accumulatedData.slice(totalPacketLength);
                } else {
                    // Data tidak cukup untuk paket lengkap, tunggu chunk berikutnya
                    break;
                }
            }
             // `accumulatedData` sekarang berisi sisa data parsial
		},
		flush(controller) {
            // Jika masih ada sisa data saat stream ditutup, itu mungkin error atau paket tidak lengkap
            if (accumulatedData.length > 0) {
                log(`UDP(DoH): Warning - Flushing stream with ${accumulatedData.length} bytes of unprocessed data.`);
            }
		}
	});

	// Writable stream untuk mengirim query DNS ke DoH dan mengirim respons kembali ke WebSocket
	const dohWritable = new WritableStream({
		async write(udpPayload) {
            // Kirim payload UDP (yang merupakan query DNS) ke server DoH
			try {
                 log(`UDP(DoH): Sending ${udpPayload.byteLength} byte DNS query to ${dohURL}`);
				const dohResponse = await fetch(dohURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/dns-message' },
					body: udpPayload, // Kirim payload DNS sebagai body
				});

				if (!dohResponse.ok) {
                    // Tangani error dari server DoH
					log(`UDP(DoH): DoH query failed with status ${dohResponse.status}: ${dohResponse.statusText}`);
                    // Baca body error jika ada
                     try {
                        const errorBody = await dohResponse.text();
                        log(`UDP(DoH): DoH error body: ${errorBody}`);
                    } catch (e) {}
                     // Kita mungkin ingin menutup koneksi atau mengirim indikasi error ke client?
                     // Untuk sekarang, kita hanya log error dan tidak mengirim apa-apa kembali.
					return; // Hentikan pemrosesan untuk query ini
				}

                // Baca respons DNS dari server DoH sebagai ArrayBuffer
				const dnsQueryResult = await dohResponse.arrayBuffer();
				const resultLength = dnsQueryResult.byteLength;
                log(`UDP(DoH): Received ${resultLength} byte DNS response from DoH.`);

                 // Buat prefix panjang 2 byte (Big Endian)
                const lengthBuffer = new Uint8Array(2);
                new DataView(lengthBuffer.buffer).setUint16(0, resultLength, false); // false = big-endian

                 // Pastikan WebSocket masih terbuka
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                     // Gabungkan header VLESS (jika belum terkirim), prefix panjang, dan hasil query DNS
                    let responseBlobParts = [];
                    if (!vlessHeaderSent) {
                         responseBlobParts.push(vlessResponseHeader);
                         vlessHeaderSent = true;
                    }
                     responseBlobParts.push(lengthBuffer.buffer); // Kirim ArrayBuffer dari prefix panjang
                     responseBlobParts.push(dnsQueryResult); // Kirim ArrayBuffer dari hasil DNS

                     webSocket.send(await new Blob(responseBlobParts).arrayBuffer());
                     log(`UDP(DoH): Sent DNS response (${resultLength} bytes payload) back to WebSocket.`);
                } else {
                     log("UDP(DoH): WebSocket closed before DoH response could be sent.");
                 }
			} catch (error) {
				log('UDP(DoH): Error during DoH fetch or processing:', error);
                // Jika fetch gagal, koneksi WebSocket mungkin sudah/akan ditutup
                safeCloseWebSocket(webSocket); // Coba tutup WS jika terjadi error DoH
			}
		}
	});

	// Hubungkan transform stream ke DoH writable stream
    try {
         transformStream.readable.pipeTo(dohWritable)
        .catch(pipeError => {
              log(`UDP(DoH): Error piping UDP data to DoH handler: ${pipeError}`);
              safeCloseWebSocket(webSocket); // Tutup WS jika pipe gagal
        });
    } catch (streamError) {
        log(`UDP(DoH): Error setting up UDP processing stream: ${streamError}`);
        safeCloseWebSocket(webSocket);
    }


	// Kembalikan writer dari transform stream agar bisa menerima data dari WebSocket
	const writer = transformStream.writable.getWriter();
	return {
		/**
		 * Menulis chunk data UDP (dengan prefix panjang) yang diterima dari WebSocket.
		 * @param {Uint8Array} chunk - Data chunk dari WebSocket.
		 */
		write: (chunk) => {
            try {
                 writer.write(chunk);
            } catch(writeError) {
                 log(`UDP(DoH): Error writing chunk to UDP processing stream: ${writeError}`);
                 // Jika penulisan gagal, batalkan writer dan tutup stream/socket
                 writer.abort(writeError).catch(e => log(`UDP(DoH): Error aborting writer: ${e}`));
                 safeCloseWebSocket(webSocket);
            }
        },
	};
}
