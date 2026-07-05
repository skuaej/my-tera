from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import ssl
import re
import urllib.parse
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

app = Flask(__name__)
CORS(app)

# Your Terabox Cookie for authenticated, full-length streams
COOKIES = {
    "ndus": "YdilaBNpeHuiby3KzHo0QgAX764-EPd9LW7VDlt3"
}

# TLS Spoofing for bypassing WAF
CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA"

class ChromeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["h2", "http/1.1"])
        kwargs['ssl_context'] = context
        return super(ChromeAdapter, self).init_poolmanager(*args, **kwargs)

def extract_multi_stream_and_thumb(url, host_url):
    match = re.search(r'/s/([A-Za-z0-9_-]+)', url)
    if not match: return {"success": False, "error": "Invalid URL"}
    
    short_id = match.group(1)
    surl = short_id[1:] if short_id.startswith('1') else short_id
    terabox_url = f"https://www.1024tera.com/sharing/link?surl={surl}"
    
    session = requests.Session()
    session.mount("https://", ChromeAdapter())
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"}

    try:
        # Extract jsToken
        resp = session.get(terabox_url, headers=headers, cookies=COOKIES, timeout=15)
        js_token = re.search(r'fn\([\'"]([A-Z0-9]+)[\'"]\)', urllib.parse.unquote(re.search(r'decodeURIComponent\([\'`"](.*?)[\'`"]\)', resp.text).group(1))).group(1)
        
        # Get Auth Keys
        api_data = session.get(f"https://www.1024tera.com/api/shorturlinfo?app_id=250528&shorturl={short_id}", headers=headers, cookies=COOKIES, timeout=15).json()
        sign, timestamp, shareid, uk = api_data["sign"], api_data["timestamp"], api_data["shareid"], api_data["uk"]
        
        # Get Files
        list_data = session.get(f"https://www.1024tera.com/share/list?app_id=250528&shorturl={short_id}&dir=%2F&root=1", headers=headers, cookies=COOKIES, timeout=15).json()
        
        files = []
        for f in list_data.get("list", []):
            if f.get("isdir") == 1: continue
            fid = f.get("fs_id")
            
            # The raw URL nobody should see
            raw_url = f"https://www.1024tera.com/share/streaming?uk={uk}&shareid={shareid}&type=M3U8_FLV_264_480&fid={fid}&sign={sign}&timestamp={timestamp}&jsToken={js_token}&esl=1&isplayer=1&ehps=1&clienttype=0&app_id=250528&web=1&channel=dubox"
            b64_url = base64.b64encode(raw_url.encode('utf-8')).decode('utf-8')
            
            files.append({
                "filename": f.get("server_filename", "Unknown_File"),
                "thumbnail": f.get("thumbs", {}).get("url3") or "",
                "stream_url": f"{host_url.rstrip('/')}/proxy?data={b64_url}",
                "vlc_url": f"{host_url.rstrip('/')}/vlc?data={b64_url}"
            })
        return {"success": True, "files": files}
    except Exception as e: 
        return {"success": False, "error": str(e)}

@app.route('/download')
def download():
    res = extract_multi_stream_and_thumb(request.args.get('url'), request.host_url)
    return jsonify(res)

@app.route('/proxy')
def proxy():
    # Keep in mind Vercel will still cut this off after 10s. Use VLC for the full video.
    try:
        target = base64.b64decode(request.args.get('data')).decode('utf-8')
    except Exception:
        return "Invalid encrypted payload", 400
        
    resp = requests.get(target, headers={"User-Agent": "Mozilla/5.0"}, cookies=COOKIES, stream=True)
    return Response(resp.iter_content(chunk_size=1024*1024), content_type=resp.headers.get('Content-Type', ''))

@app.route('/vlc')
def vlc():
    # This builds the VLC playlist and injects your ndus cookie for full, authenticated streaming.
    try:
        raw_url = base64.b64decode(request.args.get('data')).decode('utf-8')
    except Exception:
        return "Invalid encrypted payload", 400
        
    m3u = (
        "#EXTM3U\n"
        "#EXTINF:-1, Terabox Stream\n"
        "#EXTVLCOPT:http-user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
        "#EXTVLCOPT:http-referrer=https://www.1024tera.com/\n"
        f"#EXTVLCOPT:cookie=ndus={COOKIES['ndus']}\n"
        f"{raw_url}\n"
    )
    return Response(m3u, mimetype="audio/x-mpegurl", headers={"Content-Disposition": "attachment; filename=Terabox_Stream.m3u"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
