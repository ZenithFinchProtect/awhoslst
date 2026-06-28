/**
 * Combined Loader Endpoint — /api/v1/loader
 *
 * Merges the activate + create_exe dance into a single request.
 * Returns the EXE as a binary download directly.
 */

const NFA_ORIGIN = 'https://nfa-api.acode.ing';

// Shown when a key is activated against a product that has no stock left.
const RESTOCK_MESSAGE = 'SELECTED NFA OUT OF STOCK — USE SAME KEY WHEN AVAILABLE';

// True when an upstream error means activation failed because there is no
// stock available to assign to the key (rather than an invalid key).
function isOutOfStock(message) {
    return /out\s*of\s*stock|no\s+stock|sold\s*out|restock|activation\s+not\s+found|not\s+activated/i.test(message || '');
}

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Max-Age': '86400',
            },
        });
    }

    if (request.method !== 'POST') {
        return jsonResp(405, 'Method not allowed');
    }

    if (!env.NFA_API_KEY) {
        return jsonResp(500, 'Server configuration error');
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return jsonResp(400, 'Invalid JSON body');
    }

    const key = body && body.activation_key;
    if (!key) {
        return jsonResp(400, 'activation_key is required');
    }

    const nfaHeaders = {
        'X-API-Key': env.NFA_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    };

    let exeData;
    try {
        const res = await fetch(`${NFA_ORIGIN}/api/v1/create_exe`, {
            method: 'POST',
            headers: nfaHeaders,
            body: JSON.stringify({ activation_key: key }),
        });
        const data = await res.json();

        if (res.ok && data.exe_base64) {
            exeData = data;
        } else if (/activation not found/i.test(data.message || '')) {
            const actRes = await fetch(`${NFA_ORIGIN}/api/v1/activate`, {
                method: 'POST',
                headers: nfaHeaders,
                body: JSON.stringify({ activation_key: key }),
            });
            const actData = await actRes.json();

            if (!actRes.ok) {
                const m = actData.message || 'Activation failed';
                return jsonResp(actRes.status, isOutOfStock(m) ? RESTOCK_MESSAGE : m);
            }

            if (actData.exe_base64) {
                exeData = actData;
            } else {
                const exeRes = await fetch(`${NFA_ORIGIN}/api/v1/create_exe`, {
                    method: 'POST',
                    headers: nfaHeaders,
                    body: JSON.stringify({ activation_key: key }),
                });
                const exeJson = await exeRes.json();
                if (!exeRes.ok || !exeJson.exe_base64) {
                    const s = exeRes.ok ? 422 : (exeRes.status || 500);
                    const m = exeJson.message || 'Failed to build loader';
                    return jsonResp(s, isOutOfStock(m) ? RESTOCK_MESSAGE : m);
                }
                exeData = exeJson;
            }
        } else {
            const errStatus = res.ok ? 422 : res.status;
            return jsonResp(errStatus, data.message || 'Failed to build loader');
        }
    } catch (err) {
        return jsonResp(502, 'Upstream request failed: ' + err.message);
    }

    const binary = Uint8Array.from(atob(exeData.exe_base64), c => c.charCodeAt(0));
    const filename = exeData.exe_filename || 'loader.exe';

    return new Response(binary, {
        status: 200,
        headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': String(binary.length),
            'Access-Control-Allow-Origin': '*',
        },
    });
}

function jsonResp(status, message) {
    return new Response(
        JSON.stringify({ status: 'error', message }),
        { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } }
    );
}
