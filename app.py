import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB53"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

import random
import os

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
tokens_initialized = False

# Global HTTP Client for connection pooling
_client = None

async def get_client():
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=15.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            headers={'User-Agent': USERAGENT}
        )
    return _client

# Lock for initialization
init_lock = asyncio.Lock()

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "ME":
        return "uid=3825052753&password=2D99628D3083D88F0997093B5D3E65F5ED13321941FB7B3FCDFB207E203832BE"
    elif r == "BD":
        return "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7"
    elif r in {"BR", "US", "SAC", "ME"}:
        return "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24"
    else:
        return "uid=3301239795&password=DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    client = await get_client()
    resp = await client.post(url, data=payload, headers=headers)
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    max_retries = 10
    default_acc = get_account_credentials(region)
    accounts_to_try = [default_acc]
    
    if os.path.exists("accounts.txt"):
        with open("accounts.txt", "r") as f:
            lines = f.readlines()
        if lines:
            for _ in range(max_retries):
                line = random.choice(lines).strip().split(" ")
                if len(line) >= 2:
                    accounts_to_try.append(f"uid={line[0]}&password={line[1]}")
    
    for account in accounts_to_try:
        try:
            token_val, open_id = await get_access_token(account)
            if token_val == "0":
                continue 
                
            body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
            proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
            payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                'Content-Type': "application/octet-stream", 'Expect': "100-continue",
                'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
            }
            client = await get_client()
            resp = await client.post(url, data=payload, headers=headers)
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            token = msg.get('token')
            serverUrl = msg.get('serverUrl')
            
            if not token or not serverUrl:
                continue 
            
            cached_tokens[region] = {
                'token': f"Bearer {token}",
                'region': msg.get('lockRegion', region),
                'server_url': serverUrl,
                'expires_at': time.time() + 25200
            }
            print(f"Successfully cached {region} using rotation!")
            return 
        except Exception as e:
            continue
            
    print(f"Failed to find any unbanned account for {region} after {len(accounts_to_try)} tries!")

async def initialize_tokens():
    """Initialize tokens for key regions in parallel to speed up startup."""
    # BD, ME, and SG are the most important lookup regions
    primary_regions = {"BD", "ME", "SG"}
    tasks = [create_jwt(r) for r in primary_regions]
    await asyncio.gather(*tasks)
    
    # Initialize the rest in the background or lazily
    remaining_regions = SUPPORTED_REGIONS - primary_regions
    for r in remaining_regions:
        await create_jwt(r)

async def ensure_tokens_initialized():
    """Ensure tokens are initialized on the first request."""
    global tokens_initialized
    if not tokens_initialized:
        async with init_lock:
            if not tokens_initialized:
                print("Initializing tokens for the first time...")
                # We do a quick initialization of key regions first
                await initialize_tokens()
                tokens_initialized = True

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
        
    await create_jwt(region)
    info = cached_tokens.get(region)
    if not info:
        raise Exception(f"Failed to generate token for region {region}")
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    
    # Concurrent lookup: we try BD, ME, and SG simultaneously for maximum speed
    regions_to_try = [region.upper()]
    if region.upper() != "BD": regions_to_try.append("BD")
    if region.upper() != "ME": regions_to_try.append("ME")
    if region.upper() != "SG": regions_to_try.append("SG")
    
    async def try_region(current_region):
        try:
            token, lock, server = await get_token_info(current_region)
            headers = {
                'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                'Content-Type': "application/octet-stream", 'Expect': "100-continue",
                'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
                'ReleaseVersion': RELEASEVERSION
            }
            client = await get_client()
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)
            
            if resp.status_code == 429:
                if current_region in cached_tokens:
                    del cached_tokens[current_region]
                return None
            
            if resp.status_code != 200:
                return None
                
            return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
        except Exception as e:
            print(f"Region {current_region} error: {e}")
            return None

    # Run tasks concurrently
    tasks = [try_region(r) for r in regions_to_try[:3]] # Limit to top 3 for safety
    for completed_task in asyncio.as_completed(tasks):
        result = await completed_task
        if result:
            return result
            
    raise Exception("All lookup regions are currently busy or rate limited. Please try again in 1 minute.")

def format_response(data):
    return {
        "AccountInfo": {
            "AccountAvatarId": data.get("basicInfo", {}).get("headPic"),
            "AccountBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
            "AccountBPID": data.get("basicInfo", {}).get("badgeId"),
            "AccountBannerId": data.get("basicInfo", {}).get("bannerId"),
            "AccountCreateTime": data.get("basicInfo", {}).get("createAt"),
            "AccountEXP": data.get("basicInfo", {}).get("exp"),
            "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt"),
            "AccountLevel": data.get("basicInfo", {}).get("level"),
            "AccountLikes": data.get("basicInfo", {}).get("liked"),
            "AccountName": data.get("basicInfo", {}).get("nickname"),
            "AccountRegion": data.get("basicInfo", {}).get("region"),
            "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
            "AccountType": data.get("basicInfo", {}).get("accountType"),
            "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
            "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
            "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
            "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
            "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
            "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
            "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
            "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
            "Title": data.get("basicInfo", {}).get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
            "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")),
            "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
            "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
            "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
            "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId"))
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {}),
        "DevelopedBy": "Robiul"
    }

# === API Routes ===
@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "message": "Free Fire OB53 Player Info API - Developed by Robiul",
        "author": "Robiul",
        "endpoints": {
            "get_player": "/get?uid=XXXX&region=BD",
            "health_check": "/ping"
        }
    }), 200

@app.route('/get')
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    # User might provide region, otherwise we default to ME as our lookup engine
    requested_region = request.args.get('region', "BD")
    
    try:
        # Lazy initialization check
        asyncio.run(ensure_tokens_initialized())
        
        # We search for the player across the best available engines
        return_data = asyncio.run(GetAccountInformation(uid, "7", requested_region, "/GetPlayerPersonalShow"))
        formatted = format_response(return_data)
        return jsonify(formatted), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping')
def ping():
    """Keep-alive endpoint for Vercel Cron."""
    # Quickly verify tokens and refresh if needed
    asyncio.run(ensure_tokens_initialized())
    return jsonify({"status": "active", "tokens": list(cached_tokens.keys())}), 200

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        global tokens_initialized
        tokens_initialized = True
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===
# For local testing
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    
    
