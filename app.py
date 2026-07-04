"""
Terabox Direct Stream Extractor API
-----------------------------------
This Flask API acts as a middleman to bypass Terabox's web security.
It uses advanced TLS spoofing to impersonate a Google Chrome browser, 
extracts the hidden cryptographic keys (jsToken, sign, timestamp) generated 
for anonymous guests, and queries Terabox's internal APIs to generate direct 
.m3u8 streaming links and thumbnails for all files inside a shared folder.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import ssl
import re
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Initialize Flask and enable CORS so frontend web players (like HLS.js) can read the data
app = Flask(__name__)
CORS(app)

# ==========================================
# 1. TLS SPOOFING (THE FIREWALL BYPASS)
# ==========================================
# Standard Python 'requests' are often blocked by Cloudflare/WAFs because their
# SSL/TLS fingerprint looks like a bot. We manually force Python to use the exact
# cryptographic ciphers that a modern Chrome browser uses.
CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
)

class ChromeAdapter(HTTPAdapter):
    """Custom HTTP Adapter that mounts our Chrome-like TLS configuration to requests."""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["h2", "http/1.1"]) # Announce HTTP/2 support
        kwargs['ssl_context'] = context
        return super(ChromeAdapter, self).init_poolmanager(*args, **kwargs)


# ==========================================
# 2. CORE EXTRACTION LOGIC
# ==========================================
def extract_multi_stream_and_thumb(url):
    """
    Takes a Terabox wrapper link, bypasses it, and hits 3 different endpoints 
    to scrape all necessary keys for video playback.
    """
    # Extract the core ID from the URL (handles Terasharelink wrappers)
    match = re.search(r'/s/([A-Za-z0-9_-]+)', url)
    if not match:
        return {"success": False, "error": "Invalid link format. Could not extract share ID."}

    short_id = match.group(1)
    # Wrapper sites usually prepend a '1' to the ID. We strip it for the official URL.
    surl = short_id[1:] if short_id.startswith('1') else short_id
    terabox_url = f"https://www.1024tera.com/sharing/link?surl={surl}"

    # Set up our spoofed browsing session
    session = requests.Session()
    session.mount("https://", ChromeAdapter())
    
    # Standard headers to convince the server we are a human on a PC
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    }

    try:
        # ---------------------------------------------------------
        # STEP A: Scrape the jsToken from the raw HTML page
        # ---------------------------------------------------------
        response = session.get(terabox_url, headers=headers, timeout=15)
        html_content = response.text
        
        js_token = None
        # Terabox hides the token inside a URL-encoded string inside a JS decodeURIComponent function
        encoded_block = re.search(r'decodeURIComponent\([\'`"](.*?)[\'`"]\)', html_content)
        if encoded_block:
            decoded_js = urllib.parse.unquote(encoded_block.group(1))
            token_match = re.search(r'fn\([\'"]([A-Z0-9]+)[\'"]\)', decoded_js)
            if token_match:
                js_token = token_match.group(1)

        # ---------------------------------------------------------
        # STEP B: Query the hidden XHR API for auth keys
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # STEP C: Query the file list API to get fids and thumbnails
        # ---------------------------------------------------------
        extracted_files = []
        
        def process_file_list(file_list):
            """Helper function to parse the Terabox file array"""
            if file_list and len(file_list) > 0:
                for file_info in file_list:
                    if file_info.get("isdir") == 1:
                        continue # Skip folders
                        
                    fid = file_info.get("fs_id")
                    filename = file_info.get("server_filename", "Unknown_File")
                    
                    thumbnail_url = None
                    thumbs = file_info.get("thumbs", {})
                    # Find the highest resolution thumbnail (url3 is best)
                    if isinstance(thumbs, dict):
                        thumbnail_url = thumbs.get("url3") or thumbs.get("url2") or thumbs.get("url1")
                    elif isinstance(thumbs, str):
                        thumbnail_url = thumbs
                        
                    # Fallback for older Terabox API structures
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

        # Try to fetch file list using the wrapper's short_id
        list_url = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={short_id}&dir=%2F&root=1"
        list_response = session.get(list_url, headers=api_headers, timeout=15)
        
        # If that fails, try using the stripped official surl
        if not process_file_list(list_response.json().get("list")):
            list_url_2 = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={surl}&dir=%2F&root=1"
            list_response_2 = session.get(list_url_2, headers=api_headers, timeout=15)
            process_file_list(list_response_2.json().get("list"))

        # ---------------------------------------------------------
        # STEP D: Final Verification & Assembly
        # ---------------------------------------------------------
        if all([js_token, sign, timestamp, shareid, uk]) and extracted_files:
            final_response_data = []
            
            for file_data in extracted_files:
                fid = file_data["fid"]
                
                # Assemble the actual API call Terabox's video player uses
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
            return {"success": False, "error": "Failed to extract required API parameters or file list."}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ==========================================
# 3. FLASK ROUTING
# ==========================================
@app.route('/download', methods=['GET'])
def download():
    """
    Main API endpoint. 
    Usage: GET /download?url=https://teraboxshare.com/...
    """
    target_url = request.args.get('url')
    
    if not target_url:
        return jsonify({"status": "error", "message": "Missing 'url' query parameter"}), 400
        
    result = extract_multi_stream_and_thumb(target_url)
    
    # Return cleanly formatted JSON for the frontend
    if result.get("success"):
        return jsonify({
            "status": "success",
            "count": len(result["files"]),
            "data": result["files"]
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": result.get("error")
        }), 500


# Allows local testing when running the file directly (e.g., `python app.py`)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
