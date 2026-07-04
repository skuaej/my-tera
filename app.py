from flask import Flask, request, jsonify
import requests
import ssl
import re
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

app = Flask(__name__)

# --- TLS Spoofing Setup ---
CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
)

class ChromeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["h2", "http/1.1"])
        kwargs['ssl_context'] = context
        return super(ChromeAdapter, self).init_poolmanager(*args, **kwargs)

# --- Core Extraction Logic ---
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
        # STEP 1: jsToken from HTML
        response = session.get(terabox_url, headers=headers, timeout=15)
        html_content = response.text
        
        js_token = None
        encoded_block = re.search(r'decodeURIComponent\([\'`"](.*?)[\'`"]\)', html_content)
        if encoded_block:
            decoded_js = urllib.parse.unquote(encoded_block.group(1))
            token_match = re.search(r'fn\([\'"]([A-Z0-9]+)[\'"]\)', decoded_js)
            if token_match:
                js_token = token_match.group(1)

        # STEP 2: Authenticate the Share ID to get Sign & Timestamp
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

        # STEP 3: Find File IDs (fid) AND Thumbnails for ALL files
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

        # Attempt 1: API with shorturl
        list_url = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={short_id}&dir=%2F&root=1"
        list_response = session.get(list_url, headers=api_headers, timeout=15)
        if not process_file_list(list_response.json().get("list")):
            # Attempt 2: API with surl
            list_url_2 = f"https://www.1024tera.com/share/list?app_id=250528&shorturl={surl}&dir=%2F&root=1"
            list_response_2 = session.get(list_url_2, headers=api_headers, timeout=15)
            process_file_list(list_response_2.json().get("list"))

        # FINAL ASSEMBLE
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
            return {"success": False, "error": "Failed to extract required API parameters or file list."}

    except Exception as e:
        return {"success": False, "error": str(e)}

# --- Flask Endpoints ---
@app.route('/download', methods=['GET'])
def download():
    # Expects a GET request like: /download?url=https://teraboxshare.com/...
    target_url = request.args.get('url')
    
    if not target_url:
        return jsonify({"status": "error", "message": "Missing 'url' query parameter"}), 400
        
    result = extract_multi_stream_and_thumb(target_url)
    
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

if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
  
