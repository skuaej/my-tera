"""
Terabox Direct Stream Extractor & CORS Proxy API
-----------------------------------------------
This serverless API acts as a secure link extractor and real-time video proxy.
It bypasses Terabox security blocks, formats files inside folder arrays, 
and dynamically proxies video streams to bypass browser CORS restrictions.
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import ssl
import re
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

app = Flask(__name__)
# Enable CORS globally so your Vercel index.html frontend can query it freely
CORS(app)

# ==========================================
# 1. ARCHITECTURE SETUP (TLS SPOOFING)
# ==========================================
CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
)

class ChromeAdapter(HTTPAdapter):
    """Intercepts standard connection hooks to clone a real Chrome handshake footprint."""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["h2", "http/1.1"])
        kwargs['ssl_context'] = context
        return super(ChromeAdapter, self).init_poolmanager(*args, **kwargs)


# ==========================================
# 2. CORE DECRYPTION & METADATA SCRAPER
# ==========================================
def extract_multi_stream_and_thumb(url):
    match = re.search(r'/s/([A-Za-z0-9_-]+)', url)
    if not match:
        return {"success": False, "error": "Invalid link format. Could not extract share ID."}

    short_id = match.group(1)
    surl = short_id[1:] if short_id.startswith('1') else short_id
    terabox_url = f"https://www.1024tera.com/sharing/link?surl={surl}"

    session = requests.Session()
    session.mount("https://", ChromeAdapter())
    
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    }

    try:
        # STEP A: Extract browser jsToken out of encoded script tags
        response = session.get(terabox_url, headers=headers, timeout=15)
        html_content = response.text
        
        js_token = None
        encoded_block = re.search(r'decodeURIComponent\([\'`"](.*?)[\'`"]\)', html_content)
        if encoded_block:
            decoded_js = urllib.parse.unquote(encoded_block.group(1))
            token_match = re.search(r'fn\([\'"]([A-Z0-9]+)[\'"]\)', decoded_js)
            if token_match:
                js_token = token_match.group(1)

        # STEP B: Grab general verification signatures via Ajax shorturl endpoint
        api_headers = headers.copy()
        api_headers["Accept"] = "application/json, text/plain, */*"
        api_headers["Sec-Fetch-Mode"] = "cors"
        api_headers["Sec-Fetch-Dest"] = "empty"
        api_headers["Referer"] = terabox_url
        
        api_info_url = f"https://www.1024tera.com/api/shorturlinfo?app_id=250528&shorturl={short_id}"
        api_response = session.get(api_info_url, headers=api_headers, timeout=15)
        api_data = api_response.json()

        sign = api_data.get("sign")
        timestamp = api_data.get("timestamp")
        shareid = api_data.get("shareid")
        uk = api_data.get("uk")

        # STEP C: Query folder index arrays to fetch FIDs and high-res thumbnails
        extracted_files = []
        
        def process_file_list(file_list):
            if file_list and len(file_list) > 0:
                for file_info in file_list:
                    if file_info.get("isdir") == 1:
                        continue 
                        
                    fid = file_info.get("fs_id")
                    filename = file_info.get("server_filename", "Unknown_File")
                    
                    thumbnail_url = None
                    thumbs = file_info.get("thumbs", {})
                    if isinstance(thumbs, dict):
                        thumbnail_url = thumbs.get("url3") or thumbs.get("url2") or thumbs.get("url1")
                    elif isinstance(thumbs, str):
                        thumbnail_url = thumbs
                        
                    if not thumbnail_url:
                        thumbnail_url = file_info.get("thumbs_url") or file_info.get("thumbsUrl")
                        
                    if fid:
                        extracted_files.append({
                            "fid": fid,
                            "filename": filename,
                            "thumbnail": thumbnail_url
                        })
                return len(extracted_files) > 0
            return False

        list_url = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={short_id}&dir=%2F&root=1"
        list_response = session.get(list_url, headers=api_headers, timeout=15)
        
        if not process_file_list(list_response.json().get("list")):
            list_url_2 = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={surl}&dir=%2F&root=1"
            list_response_2 = session.get(list_url_2, headers=api_headers, timeout=15)
            process_file_list(list_response_2.json().get("list"))

        # STEP D: Compile Direct Stream Sources
        if all([js_token, sign, timestamp, shareid, uk]) and extracted_files:
            final_response_data = []
            for file_data in extracted_files:
                fid = file_data["fid"]
                stream_url = (
                    f"https://www.1024tera.com/share/streaming?"
                    f"uk={uk}&shareid={shareid}&type=M3U8_FLV_264_480&fid={fid}"
                    f"&sign={sign}&timestamp={timestamp}&jsToken={js_token}"
                    f"&esl=1&isplayer=1&ehps=1&clienttype=0&app_id=250528&web=1&channel=dubox"
                )
                final_response_data.append({
                    "filename": file_data["filename"],
                    "thumbnail": file_data["thumbnail"],
                    "stream_url": stream_url
                })
            return {"success": True, "files": final_response_data}
        else:
            return {"success": False, "error": "Failed to extract required parameters."}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ==========================================
# 3. WEB API API ROUTING & STREAM PROXYING
# ==========================================
@app.route('/download', methods=['GET'])
def download():
    """Returns direct parsed metadata (links, names, thumbs) as clean JSON."""
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"status": "error", "message": "Missing 'url' query parameter"}), 400
        
    result = extract_multi_stream_and_thumb(target_url)
    if result.get("success"):
        return jsonify({"status": "success", "count": len(result["files"]), "data": result["files"]}), 200
    return jsonify({"status": "error", "message": result.get("error")}), 500


@app.route('/proxy', methods=['GET'])
def proxy_video():
    """
    Pipes the actual video payload from Terabox securely back to browsers.
    Rewrites internal .m3u8 index rows natively to dissolve client-side CORS failures.
    """
    target_url = request.args.get('url')
    if not target_url:
        return "Missing target URL parameter", 400

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Referer": "https://www.1024tera.com/"
    }

    try:
        resp = requests.get(target_url, headers=headers, stream=True, timeout=15)
        content_type = resp.headers.get('Content-Type', '')

        # Check if the incoming request is target file playlist
        if 'm3u8' in target_url or 'mpegurl' in content_type.lower():
            raw_playlist = resp.text
            new_playlist = []
            
            for line in raw_playlist.splitlines():
                if line.startswith('http'):
                    encoded_url = urllib.parse.quote(line)
                    new_playlist.append(f"/proxy?url={encoded_url}")
                elif line.endswith('.ts') or line.endswith('.m3u8'):
                    base_url = target_url.rsplit('/', 1)[0]
                    full_url = f"{base_url}/{line}"
                    encoded_url = urllib.parse.quote(full_url)
                    new_playlist.append(f"/proxy?url={encoded_url}")
                else:
                    new_playlist.append(line)
                    
            return Response("\n".join(new_playlist), content_type="application/vnd.apple.mpegurl")

        # Directly stream downloaded raw data blocks
        else:
            def generate():
                for chunk in resp.iter_content(chunk_size=512 * 1024):
                    if chunk:
                        yield chunk
            return Response(generate(), content_type=content_type)

    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
