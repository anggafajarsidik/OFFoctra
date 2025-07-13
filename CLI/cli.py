import json, base64, hashlib, time, sys, re, os, shutil, asyncio, aiohttp, threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import nacl.signing
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import ssl
import random
import traceback
import platform
import signal as sys_signal

c = {
    'r': '\033[0m',
    'b': '\033[34m',
    'c': '\033[36m',
    'g': '\033[32m',
    'y': '\033[33m',
    'R': '\033[31m',
    'B': '\033[1m',
    'w': '\033[37m'
}

b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000
executor = ThreadPoolExecutor(max_workers=1)
stop_flag = threading.Event()
cancel_countdown_flag = threading.Event()

wallets_available = []
current_selection = None

OCTRASCAN_TX_URL = "https://octrascan.io/tx/"
PROXY_FILE = "proxy.txt"

DAILY_MODE_ACTIVE = False
DAILY_RUNS_PER_WALLET_PER_DAY = 0
DAILY_AMOUNT_PER_RECIPIENT = 0.0
DAILY_MIN_DELAY = 0.0
DAILY_MAX_DELAY = 0.0
DAILY_INTERVAL_HOURS = 24.0
DAILY_RECIPIENT_LIMIT = 0
DAILY_MODE_TARGET_WALLET = None
DAILY_MODE_RETRIES = 0

global_aiohttp_session = None

async def get_global_aiohttp_session():
    global global_aiohttp_session
    if global_aiohttp_session and not global_aiohttp_session.closed:
        return global_aiohttp_session
    
    connector = aiohttp.TCPConnector(ssl=ssl.create_default_context(), force_close=True)
    global_aiohttp_session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10),
        connector=connector
    )
    return global_aiohttp_session

async def get_public_ip_external(proxy_url=None):
    try:
        session_ip = await get_global_aiohttp_session()
        async with session_ip.get('https://api.ipify.org?format=json', proxy=proxy_url, ssl=False) as resp_ip:
            if resp_ip.status == 200:
                data = await resp_ip.json()
                return data.get('ip')
    except Exception:
        pass
    return "Unknown"

async def close_all_sessions():
    for wallet in wallets_available:
        if hasattr(wallet, 'aiohttp_session') and wallet.aiohttp_session and not wallet.aiohttp_session.closed:
            try:
                await wallet.aiohttp_session.close()
            except Exception:
                pass
    global global_aiohttp_session
    if global_aiohttp_session and not global_aiohttp_session.closed:
        try:
            await global_aiohttp_session.close()
        except Exception:
            pass

def signal_handler(sig, frame):
    stop_flag.set()
    cancel_countdown_flag.set()
    asyncio.create_task(close_all_sessions())
    sys.exit(0)

class Wallet:
    def __init__(self, priv, addr, rpc, name=None, proxy=None):
        self.priv = priv
        self.addr = addr
        self.rpc = rpc
        self.name = name if name else addr[:8]
        self.proxy = proxy
        self.sk = nacl.signing.SigningKey(base64.b64decode(priv))
        self.pub = base64.b64encode(self.sk.verify_key.encode()).decode()
        self.history = []
        self.cached_balance = None
        self.cached_nonce = None
        self.last_update_time = 0
        self.aiohttp_session = None
        self.proxy_public_ip = "N/A"

    def update_cache(self, nonce, balance):
        self.cached_nonce = nonce
        self.cached_balance = balance
        self.last_update_time = time.time()

    async def get_or_create_session(self, timeout=30):
        if self.aiohttp_session and not self.aiohttp_session.closed:
            return self.aiohttp_session

        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context(), force_close=True)
        self.aiohttp_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            connector=connector,
            json_serialize=json.dumps
        )
        return self.aiohttp_session

    async def get_proxy_ip(self):
        if not self.proxy:
            self.proxy_public_ip = await get_public_ip_external(None)
            return self.proxy_public_ip

        if self.proxy_public_ip == "N/A":
            self.proxy_public_ip = await get_public_ip_external(self.proxy)
        return self.proxy_public_ip

def cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def sz():
    return shutil.get_terminal_size((80, 25))

def at(x, y, t, cl=''):
    print(f"{cl}{t}{c['r']}")

async def ainp(x, y, prompt=""):
    try:
        return await asyncio.get_event_loop().run_in_executor(executor, input, prompt)
    except Exception:
        stop_flag.set()
        return ''

async def countdown_timer(duration_seconds, message_prefix="Next run in"):
    cancel_countdown_flag.clear()
    start_time = time.time()
    end_time = start_time + duration_seconds

    while time.time() < end_time and not stop_flag.is_set() and not cancel_countdown_flag.is_set():
        remaining_seconds = int(end_time - time.time())
        if remaining_seconds < 0:
            remaining_seconds = 0

        hours = remaining_seconds // 3600
        minutes = (remaining_seconds % 3600) // 60
        seconds = remaining_seconds % 60

        countdown_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        print(f"\r{c['c']}{message_prefix} {countdown_str}. (Press Ctrl+C to stop daily mode){c['r']}", end='', flush=True)
        await asyncio.sleep(1)

    print(f"\r{' ' * (len(message_prefix) + 20 + len('(Press Ctrl+C to stop daily mode)'))}", end='', flush=True)

async def awaitkey_simple(prompt_text=f"{c['y']}Press Enter to continue...{c['r']}"):
    input_future = asyncio.get_event_loop().run_in_executor(executor, input, prompt_text)
    try:
        await input_future
    except asyncio.CancelledError:
        pass
    except Exception:
        stop_flag.set()

def wait():
    asyncio.run(awaitkey_simple(prompt_text=f"{c['y']}Press Enter to continue...{c['r']}"))

async def awaitkey():
    await awaitkey_simple(prompt_text=f"{c['y']}Press Enter to continue...{c['r']}")

async def get_recipient_address_from_user(allow_random_from_file=True, prompt_text="Enter recipient address: "):
    recipients = []
    recipients_file = "recipentaddress.txt"

    if allow_random_from_file and os.path.exists(recipients_file):
        try:
            with open(recipients_file, 'r') as f:
                for line in f:
                    addr_read = line.strip()
                    if b58.match(addr_read):
                        recipients.append(addr_read)
            
            if recipients:
                print(f"{c['g']}Loaded {len(recipients)} valid addresses from '{recipients_file}'.{c['r']}")
                choice = await ainp(0, 0, f"{c['y']}Use a random address from '{recipients_file}'? [y/n/esc to cancel]: {c['r']}")
                choice_lower = choice.strip().lower()

                if choice_lower == 'y':
                    return random.choice(recipients)
                elif choice_lower == 'n':
                    return await ainp(0, 0, f"{c['y']}{prompt_text} (or [esc] to cancel): {c['r']}")
                elif choice_lower == 'esc':
                    return 'esc'
            else:
                print(f"{c['y']}No valid recipient addresses found in '{recipients_file}'.{c['r']}")
                return await ainp(0, 0, f"{c['y']}{prompt_text} (or [esc] to cancel): {c['r']}")
        except Exception as e:
            print(f"{c['R']}Error loading '{recipients_file}': {e}. Please enter address manually.{c['r']}")
            return await ainp(0, 0, f"{c['y']}{prompt_text} (or [esc] to cancel): {c['r']}")
    
    return await ainp(0, 0, f"{c['y']}{prompt_text} (or [esc] to cancel): {c['r']}")

async def load_and_limit_recipients_from_file(file_path="recipentaddress.txt", prompt_limit=True):
    recipients_original = []
    
    if not os.path.exists(file_path):
        print(f"{c['R']}Error: '{file_path}' not found in the current directory.{c['r']}")
        return None

    try:
        with open(file_path, 'r') as f:
            for line in f:
                addr_read = line.strip()
                if b58.match(addr_read):
                    recipients_original.append(addr_read)
                elif addr_read:
                    print(f"{c['y']}Warning: Invalid address '{addr_read[:20]}...' in file. Skipping.{c['r']}")
                    await asyncio.sleep(0.05)

        if not recipients_original:
            print(f"{c['R']}No valid recipient addresses found in '{file_path}' after filtering.{c['r']}")
            return None
        
        if prompt_limit:
            while True:
                limit_input = await ainp(0, 0, f"\n{c['y']}How many unique recipients from the file do you want to include in each run (Max {len(recipients_original)}, 0 for all)?: {c['r']}")
                try:
                    limit = int(limit_input.strip())
                    if limit < 0 or limit > len(recipients_original):
                        print(f"{c['R']}{c['B']}Invalid number. Please enter a number between 0 and {len(recipients_original)}.{c['r']}")
                    else:
                        return recipients_original if limit == 0 else random.sample(recipients_original, limit)
                except ValueError:
                    print(f"{c['R']}{c['B']}Invalid input. Please enter a number.{c['r']}")
        else:
            if DAILY_RECIPIENT_LIMIT == 0:
                return recipients_original
            else:
                return random.sample(recipients_original, min(DAILY_RECIPIENT_LIMIT, len(recipients_original)))

    except Exception as e:
        print(f"{c['R']}Error loading '{file_path}': {e}.{c['r']}")
        return None

def fill():
    os.system('cls' if os.name == 'nt' else 'clear')

def box(x, y, w, h, t=""):
    print(f"\n--- {c['B']}{t}{c['r']} ---")

async def spin_animation(x, y, msg):
    spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    spinner_idx = 0
    try:
        while True:
            print(f"\r{c['c']}{spinner_frames[spinner_idx]} {msg}{c['r']}", end='', flush=True)
            spinner_idx = (spinner_idx + 1) % len(spinner_frames)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        print(f"\r{' ' * (len(msg) + 3)}", end='', flush=True)

def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def decrypt_client_balance(encrypted_data, privkey_b64):
    if encrypted_data == "0" or not encrypted_data:
        return 0
    
    if not encrypted_data.startswith("v2|"):
        privkey_bytes = base64.b64decode(privkey_b64)
        salt = b"octra_encrypted_balance_v1"
        key = hashlib.sha256(salt + privkey_bytes).digest() + hashlib.sha256(privkey_bytes + salt).digest()
        key = key[:32]
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 32:
                return 0
            
            nonce = data[:16]
            tag = data[16:32]
            encrypted = data[32:]
            
            expected_tag = hashlib.sha256(nonce + encrypted + key).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                return 0
            
            decrypted = bytearray()
            key_hash = hashlib.sha256(key + nonce).digest()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_hash[i % 32])
            
            return int(decrypted.decode())
        except:
            return 0
    
    try:
        b64_data = encrypted_data[3:]
        raw = base64.b64decode(b64_data)
        
        if len(raw) < 28:
            return 0
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        key = derive_encryption_key(privkey_b64)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return 0

def derive_shared_secret_for_claim(my_privkey_b64, ephemeral_pubkey_b64):
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)
    
    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        smaller, larger = my_pubkey_bytes, eph_pub_bytes
    
    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

def decrypt_private_amount(encrypted_data, shared_secret):
    if not encrypted_data or not encrypted_data.startswith("v2|"):
        return None
    
    try:
        raw = base64.b64decode(encrypted_data[3:])
        if len(raw) < 28:
            return None
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return None

async def req(m, p, d=None, t=30, rpc_url=None, wallet_obj_for_proxy=None):
    target_rpc = rpc_url
    if not target_rpc:
        if wallet_obj_for_proxy and wallet_obj_for_proxy.rpc:
            target_rpc = wallet_obj_for_proxy.rpc
        elif current_selection and not isinstance(current_selection, list):
            target_rpc = current_selection.rpc
        else:
            return 0, "no_rpc", None

    session_to_use = None
    proxy_to_use = None

    if wallet_obj_for_proxy:
        session_to_use = await wallet_obj_for_proxy.get_or_create_session(t)
        proxy_to_use = wallet_obj_for_proxy.proxy
    else:
        session_to_use = await get_global_aiohttp_session()
        if wallets_available and wallets_available[0].proxy: 
            available_proxies_in_wallets = [w.proxy for w in wallets_available if w.proxy]
            if available_proxies_in_wallets:
                proxy_to_use = random.choice(available_proxies_in_wallets)
    
    try:
        url = f"{target_rpc}{p}"
        kwargs = {}
        if m == 'POST' and d:
            kwargs['json'] = d
        if proxy_to_use:
            kwargs['proxy'] = proxy_to_use

        async with getattr(session_to_use, m.lower())(url, **kwargs) as resp:
            text = await resp.text()
            
            try:
                j = json.loads(text) if text.strip() else None
            except:
                j = None
            
            return resp.status, text, j
    except asyncio.TimeoutError:
        return 0, "timeout", None
    except Exception as e:
        return 0, str(e), None
    finally:
        if not wallet_obj_for_proxy and session_to_use and not session_to_use.closed:
            if session_to_use is global_aiohttp_session:
                pass
            else:
                try:
                    await session_to_use.close()
                except Exception:
                    pass

async def req_private(path, method='GET', data=None, wallet=None, retries=0):
    wallet_obj = wallet
    if not wallet_obj or not wallet_obj.priv:
        return False, {"error": "No active wallet or private key available."}

    headers = {"X-Private-Key": wallet_obj.priv}
    
    session_to_use = await wallet_obj.get_or_create_session()
    proxy_to_use = wallet_obj.proxy

    for attempt in range(retries + 1):
        try:
            url = f"{wallet_obj.rpc}{path}"
            kwargs = {'headers': headers}
            if method == 'POST' and data:
                kwargs['json'] = data
            if proxy_to_use:
                kwargs['proxy'] = proxy_to_use

            async with getattr(session_to_use, method.lower())(url, **kwargs) as resp:
                text = await resp.text()
                
                if resp.status == 200:
                    try:
                        return True, json.loads(text) if text.strip() else {}
                    except:
                        return False, {"error": "Invalid JSON response"}
                else:
                    error_msg = {"error": f"HTTP {resp.status} - {text[:100]}"}
                    if attempt < retries:
                        print(f"{c['y']}    Retry {attempt+1}/{retries}: Private request failed! Error: {error_msg['error']}. Retrying...{c['r']}")
                        await asyncio.sleep(random.uniform(1, 3))
                    else:
                        return False, error_msg
                        
        except asyncio.TimeoutError:
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Private request timed out. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
            else:
                return False, {"error": "Request timed out"}
        except Exception as e:
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Private request failed due to error: {e}. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
            else:
                return False, {"error": str(e)}
    return False, {"error": "Max retries exceeded"}

async def st(wallet_obj):
    now = time.time()
    if wallet_obj.cached_balance is not None and (now - wallet_obj.last_update_time) < 30:
        return wallet_obj.cached_nonce, wallet_obj.cached_balance
    
    results = await asyncio.gather(
        req('GET', f'/balance/{wallet_obj.addr}', rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj),
        req('GET', '/staging', 5, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj),
        return_exceptions=True
    )
    
    s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
    s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
    
    cn, cb = None, None
    if s == 200 and j:
        cn = int(j.get('nonce', 0))
        cb = float(j.get('balance', 0))
        if s2 == 200 and j2:
            our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == wallet_obj.addr]
            if our:
                cn = max(cn, max(int(tx.get('nonce', 0)) for tx in our))
    elif s == 404:
        cn, cb = 0, 0.0
    elif s == 200 and t and not j:
        try:
            parts = t.strip().split()
            if len(parts) >= 2:
                cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                cn = int(parts[1]) if parts[1].isdigit() else 0
            else:
                cn, cb = None, None
        except:
            cn, cb = None, None
    
    wallet_obj.update_cache(cn, cb)
    return cn, cb

async def get_encrypted_balance(wallet_obj, retries=0):
    ok, result = await req_private(f"/view_encrypted_balance/{wallet_obj.addr}", wallet=wallet_obj, retries=retries)
    
    if ok:
        try:
            return {
                "public": float(result.get("public_balance", "0").split()[0]),
                "public_raw": int(result.get("public_balance_raw", "0")),
                "encrypted": float(result.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(result.get("encrypted_balance_raw", "0")),
                "total": float(result.get("total_balance", "0").split()[0])
            }
        except:
            return None
    else:
        return None

async def encrypt_balance(amount, wallet_obj, retries=0):
    enc_data = await get_encrypted_balance(wallet_obj, retries=retries)
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    new_encrypted_raw = current_encrypted_raw + int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, wallet_obj.priv)
    
    data = {
        "address": wallet_obj.addr,
        "amount": str(int(amount * μ)),
        "private_key": wallet_obj.priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/encrypt_balance', data, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def decrypt_balance(amount, wallet_obj, retries=0):
    enc_data = await get_encrypted_balance(wallet_obj, retries=retries)
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    if current_encrypted_raw < int(amount * μ):
        return False, {"error": "insufficient encrypted balance"}
    
    new_encrypted_raw = current_encrypted_raw - int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, wallet_obj.priv)
    
    data = {
        "address": wallet_obj.addr,
        "amount": str(int(amount * μ)),
        "private_key": wallet_obj.priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/decrypt_balance', data, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def get_address_info(address, rpc_url, retries=0):
    s, t, j = await req('GET', f'/address/{address}', rpc_url=rpc_url)
    if s == 200:
        return j
    for attempt in range(retries):
        await asyncio.sleep(random.uniform(0.5, 2))
        s, t, j = await req('GET', f'/address/{address}', rpc_url=rpc_url)
        if s == 200: return j
    return None

async def get_public_key(address, rpc_url, retries=0):
    s, t, j = await req('GET', f'/public_key/{address}', rpc_url=rpc_url)
    if s == 200:
        return j.get("public_key")
    for attempt in range(retries):
        await asyncio.sleep(random.uniform(0.5, 2))
        s, t, j = await req('GET', f'/public_key/{address}', rpc_url=rpc_url)
        if s == 200: return j.get("public_key")
    return None

async def create_private_transfer(to_addr, amount, wallet_obj, retries=0):
    for attempt in range(retries + 1):
        addr_info = await get_address_info(to_addr, wallet_obj.rpc, retries=1)
        if not addr_info or not addr_info.get("has_public_key"):
            error_msg = {"error": "Recipient has no public key"}
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Transfer failed! Error: {error_msg['error']}. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
                continue
            return False, error_msg
        
        to_public_key = await get_public_key(to_addr, wallet_obj.rpc, retries=1)
        if not to_public_key:
            error_msg = {"error": "Cannot get recipient public key"}
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Transfer failed! Error: {error_msg['error']}. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
                continue
            return False, error_msg
        
        data = {
            "from": wallet_obj.addr,
            "to": to_addr,
            "amount": str(int(amount * μ)),
            "from_private_key": wallet_obj.priv,
            "to_public_key": to_public_key
        }
        
        s, t, j = await req('POST', '/private_transfer', data, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
        if s == 200:
            return True, j
        else:
            error_msg = {"error": j.get("error", t) if j else t}
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Private transfer failed! Error: {error_msg['error']}. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
            else:
                return False, error_msg
    return False, {"error": "Max retries exceeded for private transfer creation"}

async def get_pending_transfers(wallet_obj, retries=0):
    ok, result = await req_private(f"/pending_private_transfers?address={wallet_obj.addr}", wallet=wallet_obj, retries=retries)
    
    if ok:
        transfers = result.get("pending_transfers", [])
        return transfers
    else:
        return []

async def claim_private_transfer(transfer_id, wallet_obj, retries=0):
    for attempt in range(retries + 1):
        data = {
            "recipient_address": wallet_obj.addr,
            "private_key": wallet_obj.priv,
            "transfer_id": transfer_id
        }
        
        s, t, j = await req('POST', '/claim_private_transfer', data, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
        if s == 200:
            return True, j
        else:
            error_msg = {"error": j.get("error", t) if j else t}
            if attempt < retries:
                print(f"{c['y']}    Retry {attempt+1}/{retries}: Claim failed! Error: {error_msg['error']}. Retrying...{c['r']}")
                await asyncio.sleep(random.uniform(1, 3))
            else:
                return False, error_msg
    return False, {"error": "Max retries exceeded for private transfer claim"}

async def gh(wallet_obj):
    now = time.time()
    if now - wallet_obj.last_update_time < 60 and wallet_obj.history:
        return
    s, t, j = await req('GET', f'/address/{wallet_obj.addr}?limit=20', rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
    if s != 200 or (not j and not t):
        return
    
    if j and 'recent_transactions' in j:
        tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
        tx_results = await asyncio.gather(*[req('GET', f'/tx/{hash}', 5, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj) for hash in tx_hashes], return_exceptions=True)
        
        existing_hashes = {tx['hash'] for tx in wallet_obj.history}
        nh = []
        
        for i, (ref, result) in enumerate(zip(j.get('recent_transactions', []), tx_results)):
            if isinstance(result, Exception):
                continue
            s2, _, j2 = result
            if s2 == 200 and j2 and 'parsed_tx' in j2:
                p = j2['parsed_tx']
                tx_hash = ref['hash']
                
                if tx_hash in existing_hashes:
                    continue
                
                ii = p.get('to') == wallet_obj.addr
                ar = p.get('amount_raw', p.get('amount', '0'))
                a = float(ar) if '.' in str(ar) else int(ar) / μ
                msg = None
                if 'data' in j2:
                    try:
                        data = json.loads(j2['data'])
                        msg = data.get('message')
                    except:
                        pass
                nh.append({
                    'time': datetime.fromtimestamp(p.get('timestamp', 0)),
                    'hash': tx_hash,
                    'amt': a,
                    'to': p.get('to') if not ii else p.get('from'),
                    'type': 'in' if ii else 'out',
                    'ok': True,
                    'nonce': p.get('nonce', 0),
                    'epoch': ref.get('epoch', 0),
                    'msg': msg
                })
        
        oh = datetime.now() - timedelta(hours=1)
        wallet_obj.history[:] = sorted(nh + [tx for tx in wallet_obj.history if tx.get('time', datetime.now()) > oh], key=lambda x: x['time'], reverse=True)[:50]
        wallet_obj.last_update_time = now

def mk(to, a, n, wallet_obj, msg=None):
    tx = {
        "from": wallet_obj.addr,
        "to_": to,
        "amount": str(int(a * μ)),
        "nonce": int(n),
        "ou": "1" if a < 1000 else "3",
        "timestamp": time.time()
    }
    if msg:
        tx["message"] = msg
    bl = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    sig = base64.b64encode(wallet_obj.sk.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=wallet_obj.pub)
    return tx, hashlib.sha256(bl.encode()).hexdigest()

async def snd(tx, wallet_obj, retries=0):
    for attempt in range(retries + 1):
        s, t, j = await req('POST', '/send-tx', tx, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
        if s == 200:
            if j and j.get('status') == 'accepted':
                return True, j.get('tx_hash', ''), 0, j
            elif t.lower().startswith('ok'):
                return True, t.split()[-1], 0, None
        
        error_msg = json.dumps(j) if j else t
        if attempt < retries:
            print(f"{c['y']}    Retry {attempt+1}/{retries}: Transaction failed! Error: {error_msg[:70]}. Retrying...{c['r']}")
            await asyncio.sleep(random.uniform(1, 3))
        else:
            return False, error_msg, 0, j

async def expl(wallet_obj=None):
    cls()
    print(f"\n--- {c['B']}Wallet Explorer{c['r']} ---")

    if wallet_obj:
        print(f"\n{c['B']}Wallet:{c['r']} {c['c']}{wallet_obj.name}{c['r']} ({wallet_obj.addr[:8]}...)\n")
        
        proxy_ip_for_wallet = await wallet_obj.get_proxy_ip()
        proxy_status_color = c['g'] if wallet_obj.proxy else c['y']
        proxy_status_text = "Active" if wallet_obj.proxy else "Inactive"
        print(f"  {c['c']}Proxy Status:{c['r']} {proxy_status_color}{proxy_status_text}{c['r']} | {c['c']}Public IP:{c['r']} {proxy_ip_for_wallet}\n")

        n, b = await st(wallet_obj)
        await gh(wallet_obj)
        print(f"  {c['c']}Address:{c['r']} {wallet_obj.addr}")
        print(f"  {c['c']}Balance:{c['r']} {f'{c['B']}{c['g']}{b:.6f} oct{c['r']}' if b is not None else '---'}")
        print(f"  {c['c']}Nonce:{c['r']}   {str(n) if n is not None else '---'}")
        print(f"  {c['c']}Public Key:{c['r']} {wallet_obj.pub}")
        print(f"  {c['c']}RPC:{c['r']} {wallet_obj.rpc}\n")
        
        try:
            enc_data = await get_encrypted_balance(wallet_obj)
            if enc_data:
                print(f"  {c['c']}Encrypted Balance:{c['r']} {c['B']}{c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
        
                pending = await get_pending_transfers(wallet_obj)
                if pending:
                    print(f"  {c['c']}Claimable:{c['r']} {c['B']}{c['g']}{len(pending)} transfers{c['r']}")
        except Exception as e:
            print(f"  {c['R']}Error getting encrypted balance: {e}{c['r']}")
    
        _, _, j = await req('GET', '/staging', 2, rpc_url=wallet_obj.rpc, wallet_obj_for_proxy=wallet_obj)
        sc = len([tx for tx in j.get('staged_transactions', []) if tx.get('from') == wallet_obj.addr]) if j else 0
        print(f"  {c['c']}Staging:{c['r']} {f'{sc} pending' if sc else 'none'} {c['y'] if sc else c['w']}\n")
        
        print(f"--- {c['B']}Recent Transactions{c['r']} ---")
        if not wallet_obj.history:
            print(f"{c['y']}No transactions yet.{c['r']}")
        else:
            print(f"{c['c']}Time     Type  Amount      Address                   Status{c['r']}")
            print(f"{c['w']}----------------------------------------------------------------{c['r']}")
            seen_hashes = set()
            display_count = 0
            sorted_h = sorted(wallet_obj.history, key=lambda x: x['time'], reverse=True)
            for tx in sorted_h:
                if tx['hash'] in seen_hashes:
                    continue
                seen_hashes.add(tx['hash'])
            
                if display_count >= 10:
                    print(f"{c['y']}...and more{c['r']}")
                    break
                
                is_pending = not tx.get('epoch')
                time_color = c['y'] if is_pending else c['w']
                
                tx_type_color = c['g'] if tx['type'] == 'in' else c['R']
                tx_type_text = "in " if tx['type'] == 'in' else "out"
                
                status_color = c['y'] if is_pending else c['c']
                status_text = "pen" if is_pending else f"e{tx.get('epoch', 0)}"

                msg_indicator = f" {c['c']}(msg){c['r']}" if tx.get('msg') else ""

                print(f"{time_color}{tx['time'].strftime('%H:%M:%S')}{c['r']} "
                      f"{tx_type_color}{tx_type_text}{c['r']} "
                      f"{c['w']}{float(tx['amt']):>10.6f}{c['r']} "
                      f"{c['y']}{str(tx.get('to', '---'))[:20]}...{c['r']} "
                      f"{status_color}{status_text}{c['r']}{msg_indicator}")
                display_count += 1

    else:
        print(f"\n--- {c['B']}All Wallets Overview{c['r']} ---\n")
        if not wallets_available:
            print(f"{c['y']}No wallets loaded.{c['r']}")
            return

        ip_tasks = []
        for w in wallets_available:
            ip_tasks.append(w.get_proxy_ip())
        await asyncio.gather(*ip_tasks)

        for i, w in enumerate(wallets_available):
            print(f"  {c['B']}[{i+1}]{c['r']}: {c['B']}{w.name}{c['r']} ({w.addr[:8]}...)\n")
            n, b = await st(w)
            print(f"    {c['c']}Balance:{c['r']} {f'{c['g']}{b:.6f} oct{c['r']}' if b is not None else '---'}")
            print(f"    {c['c']}Nonce:{c['r']}   {str(n) if n is not None else '---'}")
            print(f"    {c['c']}Proxy IP:{c['r']} {w.proxy_public_ip}\n")
            try:
                enc_data = await get_encrypted_balance(w)
                if enc_data:
                    print(f"    {c['c']}Encrypted:{c['r']} {c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
            except Exception as e:
                print(f"    {c['R']}Error encrypted balance: {e}{c['r']}")
            
            pending = await get_pending_transfers(w)
            if pending:
                print(f"    {c['c']}Claimable:{c['r']} {c['g']}{len(pending)} transfers{c['r']}")
            print("-" * 40)

def menu(active_wallet_name):
    cls()
    print(f"\n--- {c['B']}Commands{c['r']} ---\n")
    print(f"{c['B']}Active Wallet:{c['r']} {c['c']}{active_wallet_name}{c['r']}\n")
    print(f"{c['w']}[1] Send Transaction{c['r']}")
    print(f"{c['w']}[2] Refresh Wallet(s){c['r']}")
    print(f"{c['w']}[3] Multi Send from File{c['r']}")
    print(f"{c['w']}[4] Encrypt Balance{c['r']}")
    print(f"{c['w']}[5] Decrypt Balance{c['r']}")
    print(f"{c['w']}[6] Private Transfer{c['r']}")
    print(f"{c['w']}[7] Claim Transfers{c['r']}")
    print(f"{c['w']}[8] Export Keys{c['r']}")
    print(f"{c['w']}[9] Clear History{c['r']}")
    print(f"{c['w']}[0] Exit{c['r']}")
    print(f"\n{c['y']}[s] Select Wallet / All Wallets{c['r']}\n")
    
    cmd_input = input(f"{c['B']}{c['y']}Enter command: {c['r']}")
    return cmd_input.strip().lower()

async def scr():
    pass

async def tx_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Send Transaction ({wallet_obj.name}){c['r']} ---\n")

        to = await get_recipient_address_from_user(
            allow_random_from_file=True, 
            prompt_text="To address:"
        )
        to = to.strip()
        if not to or to.lower() == 'esc':
            return

        if not b58.match(to):
            print(f"{c['R']}{c['B']}Invalid address!{c['r']}")
            await awaitkey()
            return
        if to == wallet_obj.addr:
            print(f"{c['R']}{c['B']}Error: Cannot send to the same address as the sender.{c['r']}")
            print(f"{c['y']}Use encrypt/decrypt operations for internal balance changes.{c['r']}")
            await awaitkey()
            return
        print(f"To: {c['g']}{to}{c['r']}")

        amount_input = await ainp(0, 0, f"\n{c['y']}Amount: (or [esc] to cancel): {c['r']}")
        a_str = amount_input.strip()
        if not a_str or a_str.lower() == 'esc':
            return
        if not re.match(r"^\d+(\.\d+)?$", a_str) or float(a_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        a = float(a_str)
        print(f"Amount: {c['g']}{a:.6f} oct{c['r']}")

        msg_input = await ainp(0, 0, f"\n{c['y']}Message (optional, max 1024, or Enter to skip): {c['r']}")
        msg = msg_input.strip()
        if not msg:
            msg = None
        elif len(msg) > 1024:
            msg = msg[:1024]
            print(f"{c['y']}Message truncated to 1024 chars{c['r']}")
        
        while True:
            times_input = await ainp(0, 0, f"\n{c['y']}How many times do you want to send this transaction (1 for single send)?: {c['r']}")
            times_str = times_input.strip()
            if not times_str.isdigit() or int(times_str) <= 0:
                print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
            else:
                num_times = int(times_str)
                break
        
        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between transactions (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
        
        while True:
            max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between transactions (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

        print(f"\n--- {c['B']}Summary{c['r']} ---")
        print(f"Sending {c['B']}{c['g']}{a:.6f} oct{c['r']}")
        print(f"To:  {c['g']}{to}{c['r']}")
        if msg:
            print(f"Msg: {c['c']}{msg[:50]}{'...' if len(msg) > 50 else ''}{c['r']}")
        print(f"Number of times: {c['c']}{num_times}{c['r']}")
        print(f"Delay per transaction: {c['c']}{min_delay:.1f}-{max_delay:.1f} seconds{c['r']}")
        
        fee_per_tx = 0.001 if a < 1000 else 0.003
        total_estimated_fees = fee_per_tx * num_times
        total_amount_needed = (a * num_times) + total_estimated_fees

        print(f"Total estimated amount (including fees): {c['y']}{total_amount_needed:.6f} oct{c['r']}")
        
        spin_task_balance = asyncio.create_task(spin_animation(0, 0, "Fetching balance & nonce..."))
        n, b = await st(wallet_obj)
        spin_task_balance.cancel()
        try: await spin_task_balance
        except asyncio.CancelledError: pass
        print("")

        if n is None:
            print(f"{c['R']}{c['B']}Failed to get nonce!{c['r']}")
            await awaitkey()
            return
        if b is None or b < total_amount_needed:
            print(f"{c['R']}{c['B']}Insufficient balance ({b:.6f} < {total_amount_needed:.6f})!{c['r']}")
            await awaitkey()
            return

        print(f"Fee per transaction: {c['y']}{fee_per_tx:.6f} oct (starting nonce: {n + 1}){c['r']}\n")
        
        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm sending {num_times} times? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return
        
        success_count_loop = 0
        fail_count_loop = 0
        current_nonce_loop = n + 1

        print(f"{c['B']}Enter number of retries for each transaction (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        for i in range(num_times):
            print(f"\n{c['c']}Attempt {i+1}/{num_times}: Sending... (Nonce: {current_nonce_loop}){c['r']}", end='', flush=True)
            spin_task_tx = asyncio.create_task(spin_animation(0, 0, ""))
            
            t, _ = mk(to, a, current_nonce_loop, wallet_obj, msg)
            ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)
            
            spin_task_tx.cancel()
            try: await spin_task_tx
            except asyncio.CancelledError: pass
            print(f"\r{' ' * (len(f'Attempt {i+1}/{num_times}: Sending... (Nonce: {current_nonce_loop})') + 3)}", end='', flush=True)

            if ok:
                success_count_loop += 1
                print(f"{c['g']}  ✓ Accepted! Hash: {hs}{c['r']}")
                print(f"  {c['w']}Time: {dt:.2f}s{c['r']}")
                if r and 'pool_info' in r:
                    print(f"  {c['y']}Pool: {r['pool_info'].get('total_pool_size', 0)} txs pending{c['r']}")
                print(f"  {c['c']}Explorer: {OCTRASCAN_TX_URL}{hs}{c['r']}\n")
            
                wallet_obj.history.append({
                    'time': datetime.now(),
                    'hash': hs,
                    'amt': a,
                    'to': to,
                    'type': 'out',
                    'ok': True,
                    'msg': msg
                })
            else:
                fail_count_loop += 1
                print(f"{c['R']}  ✗ Failed! Error: {str(hs)}{c['r']}\n")
            
            current_nonce_loop += 1
            if i < num_times - 1:
                delay_sec = random.uniform(min_delay, max_delay)
                print(f"{c['c']}  Delaying for {delay_sec:.1f} seconds...{c['r']}")
                await asyncio.sleep(delay_sec)

        wallet_obj.last_update_time = 0
        print(f"--- {c['B']}Loop Send Summary{c['r']} ---")
        final_color = c['g'] if fail_count_loop == 0 else c['R']
        print(f"{final_color}{c['B']}Total: {success_count_loop} successful, {fail_count_loop} failed.{c['r']}")
        await awaitkey()

    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in tx_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def multi_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Multi Send to Randomly Ordered Recipients ({wallet_obj.name}){c['r']} ---\n")
        
        recipients_shuffled_for_run = await load_and_limit_recipients_from_file(prompt_limit=True)
        if recipients_shuffled_for_run is None:
            await awaitkey()
            return
        
        if not recipients_shuffled_for_run:
            print(f"{c['R']}No recipients selected for this run.{c['r']}")
            await awaitkey()
            return

        print(f"{c['g']}Selected {len(recipients_shuffled_for_run)} unique recipients for this run.{c['r']}")
        
        amount_input = await ainp(0, 0, f"\n{c['y']}Enter amount for EACH recipient (e.g., 0.1): {c['r']}")
        amount_str = amount_input.strip()
        if not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        a = float(amount_str)
        
        global DAILY_MODE_ACTIVE, DAILY_RUNS_PER_WALLET_PER_DAY, DAILY_AMOUNT_PER_RECIPIENT, DAILY_MIN_DELAY, DAILY_MAX_DELAY, DAILY_RECIPIENT_LIMIT, DAILY_MODE_TARGET_WALLET, DAILY_MODE_RETRIES

        daily_choice = await ainp(0, 0, f"\n{c['B']}{c['y']}Do you want to run this Multi Send daily (every {DAILY_INTERVAL_HOURS} hours)? [y/n]: {c['r']}")
        if daily_choice.strip().lower() == 'y':
            DAILY_MODE_ACTIVE = True
            DAILY_MODE_TARGET_WALLET = wallet_obj
            
            while True:
                runs_input = await ainp(0, 0, f"{c['y']}How many times do you want to repeat Multi Send (1 for single run)?: {c['r']}")
                if runs_input.strip().isdigit() and int(runs_input.strip()) > 0:
                    DAILY_RUNS_PER_WALLET_PER_DAY = int(runs_input.strip())
                    break
                else:
                    print(f"{c['R']}{c['B']}Invalid input. Please enter a positive integer.{c['r']}")
            
            DAILY_AMOUNT_PER_RECIPIENT = a
            DAILY_RECIPIENT_LIMIT = len(recipients_shuffled_for_run)
            
            while True:
                min_delay_input = await ainp(0, 0, f"{c['y']}Minimum delay between transactions (seconds) for daily runs?: {c['r']}")
                try:
                    min_delay_val = float(min_delay_input.strip())
                    if min_delay_val < 0: raise ValueError
                    DAILY_MIN_DELAY = min_delay_val
                    break
                except ValueError:
                    print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
            
            while True:
                max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between transactions (seconds) for daily runs?: {c['r']}")
                try:
                    max_delay_val = float(max_delay_input.strip())
                    if max_delay_val < DAILY_MIN_DELAY: raise ValueError
                    DAILY_MAX_DELAY = max_delay_val
                    break
                except ValueError:
                    print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

            print(f"{c['B']}Enter number of retries for each transaction in daily mode (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
            retries_input = await ainp(0,0, '')
            try:
                DAILY_MODE_RETRIES = int(retries_input.strip())
                if DAILY_MODE_RETRIES < 0: raise ValueError
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
                DAILY_MODE_RETRIES = 0

            print(f"{c['g']}Daily Multi Send configured for wallet '{wallet_obj.name}'! Script will now run in automated daily mode.{c['r']}")
            print(f"{c['y']}To stop, press Ctrl+C.{c['r']}")
            await awaitkey()
            return
        else:
            while True:
                times_input = await ainp(0, 0, f"\n{c['y']}How many times do you want to repeat this entire multi-send (1 for single run)?: {c['r']}")
                times_str = times_input.strip()
                if not times_str.isdigit() or int(times_str) <= 0:
                    print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
                else:
                    num_runs = int(times_str)
                    break

        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between transactions (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
        
        while True:
            max_delay_input = await ainp(0, 0, f"\n{c['y']}Maximum delay between transactions (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

        total_tx_per_run_base = len(recipients_shuffled_for_run)
        fee_per_tx = 0.001 if a < 1000 else 0.003
        total_fees_per_run = fee_per_tx * total_tx_per_run_base
        total_amount_needed_per_run = (a * total_tx_per_run_base) + total_fees_per_run

        overall_total_transactions = total_tx_per_run_base * num_runs
        overall_total_cost = total_amount_needed_per_run * num_runs

        print(f"\n--- {c['B']}Summary ({wallet_obj.name}) Multi Send (Random Order){c['r']} ---")
        print(f"Sending {c['g']}{a:.6f} OCT{c['r']} to {total_tx_per_run_base} addresses in random order.")
        print(f"Repeating this process {c['c']}{num_runs}{c['r']} time(s).")
        print(f"Delay between transactions: {c['c']}{min_delay:.1f}-{max_delay:.1f} seconds{c['r']}")
        print(f"Total transactions to attempt: {c['B']}{c['y']}{overall_total_transactions}{c['r']}")
        print(f"Estimated total cost (including fees): {c['B']}{c['g']}{overall_total_cost:.6f} OCT{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm this multi-send operation? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each transaction (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Multi-Send from Wallet {wallet_obj.name}...{c['r']} ---\n")

        overall_success_tx = 0
        overall_failed_tx = 0
        
        n_initial, b_initial = await st(wallet_obj)
        current_nonce_loop = n_initial + 1

        for run_idx in range(num_runs):
            print(f"{c['B']}--- Run {run_idx+1}/{num_runs} (Randomizing order) ---{c['r']}")
            recipients_current_run = recipients_shuffled_for_run[:]
            random.shuffle(recipients_current_run)

            for i, recipient_addr in enumerate(recipients_current_run):
                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}  Skipping: Cannot send to sender's own address ({recipient_addr[:20]}).{c['r']}")
                    overall_failed_tx += 1
                    continue

                print(f"{c['c']}[{i+1}/{len(recipients_current_run)}] Sending {a:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce_loop}){c['r']}", end='', flush=True)
                t, _ = mk(recipient_addr, a, current_nonce_loop, wallet_obj)
                ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)
                
                print(f"\r{' ' * (len(f'[{i+1}/{len(recipients_current_run)}] Sending {a:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce_loop})') + 3)}", end='', flush=True)

                if ok:
                    overall_success_tx += 1
                    print(f"{c['g']}  ✓ Accepted! Hash: {hs}{c['r']}")
                    print(f"  {c['w']}Time: {dt:.2f}s{c['r']}")
                    if r and 'pool_info' in r:
                        print(f"  {c['y']}Pool: {r['pool_info'].get('total_pool_size', 0)} txs pending{c['r']}")
                    print(f"  {c['c']}Explorer: {OCTRASCAN_TX_URL}{hs}{c['r']}\n")
                    wallet_obj.history.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': a,
                        'to': recipient_addr,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    overall_failed_tx += 1
                    print(f"{c['R']}  ✗ Failed! Error: {str(hs)}{c['r']}\n")
                current_nonce_loop += 1
                
                if i < len(recipients_current_run) - 1 or run_idx < num_runs - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}  Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)
            
            wallet_obj.last_update_time = 0

        print(f"\n--- {c['B']}Multi-send Summary ({wallet_obj.name}){c['r']} ---")
        final_color = c['g'] if overall_failed_tx == 0 else c['R']
        print(f"{final_color}{c['B']}Completed multi-send: {overall_success_tx} successful, {overall_failed_tx} failed.{c['r']}")
        wallet_obj.last_update_time = 0

        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in multi_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def encrypt_balance_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Encrypt Balance ({wallet_obj.name}){c['r']} ---\n")
        
        spin_task = asyncio.create_task(spin_animation(0, 0, "Fetching balance info..."))
        _, pub_bal = await st(wallet_obj)
        enc_data = await get_encrypted_balance(wallet_obj)
        spin_task.cancel()
        try: await spin_task
        except asyncio.CancelledError: pass
        print("")

        if not enc_data:
            print(f"{c['R']}Cannot get encrypted balance info.{c['r']}")
            await awaitkey()
            return
        
        print(f"Public Balance: {c['w']}{pub_bal:.6f} oct{c['r']}")
        print(f"Encrypted: {c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
        print(f"Total Balance: {c['g']}{enc_data['total']:.6f} oct{c['r']}\n")
        
        max_encrypt = enc_data['public_raw'] / μ - (0.001 if enc_data['public_raw'] / μ > 0.001 else 0)
        if max_encrypt <= 0:
            print(f"{c['R']}Insufficient public balance (need > 0.001 oct for fees or minimum encryption amount).{c['r']}")
            await awaitkey()
            return
        
        print(f"Max encryptable: {c['y']}{max_encrypt:.6f} oct{c['r']}\n")
        
        amount_input = await ainp(0, 0, f"{c['y']}Amount to encrypt: {c['r']}")
        amount_str = amount_input.strip()
        
        if not amount_str or not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            return
        
        amount = float(amount_str)
        if amount > max_encrypt:
            print(f"{c['R']}Amount too large (max: {max_encrypt:.6f}){c['r']}")
            await awaitkey()
            return
        
        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Encrypt {amount:.6f} oct? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return
        
        print(f"{c['B']}Enter number of retries for encryption (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        spin_task_enc = asyncio.create_task(spin_animation(0, 0, "Encrypting balance..."))
        
        ok, result = await encrypt_balance(amount, wallet_obj, retries=num_retries)
        
        spin_task_enc.cancel()
        try: await spin_task_enc
        except asyncio.CancelledError: pass
        print("")
        
        if ok:
            print(f"{c['g']}{c['B']}✓ Encryption submitted!{c['r']}")
            print(f"{c['g']}Tx hash: {result.get('tx_hash', 'unknown')}{c['r']}")
            print(f"{c['g']}Will process in next epoch{c['r']}")
            wallet_obj.last_update_time = 0
        else:
            print(f"{c['R']}{c['B']}✗ Error: {result.get('error', 'unknown')}{c['r']}")
        
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in encrypt_balance_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def decrypt_balance_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Decrypt Balance ({wallet_obj.name}){c['r']} ---\n")
        
        spin_task = asyncio.create_task(spin_animation(0, 0, "Fetching balance info..."))
        _, pub_bal = await st(wallet_obj)
        enc_data = await get_encrypted_balance(wallet_obj)
        spin_task.cancel()
        try: await spin_task
        except asyncio.CancelledError: pass
        print("")

        if not enc_data:
            print(f"{c['R']}Cannot get encrypted balance info.{c['r']}")
            await awaitkey()
            return
        
        print(f"Public Balance: {c['w']}{pub_bal:.6f} oct{c['r']}")
        print(f"Encrypted: {c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
        print(f"Total Balance: {c['g']}{enc_data['total']:.6f} oct{c['r']}\n")
        
        if enc_data['encrypted_raw'] == 0:
            print(f"{c['R']}No encrypted balance to decrypt.{c['r']}")
            await awaitkey()
            return
        
        max_decrypt = enc_data['encrypted_raw'] / μ
        print(f"Max decryptable: {c['y']}{max_decrypt:.6f} oct{c['r']}\n")
        
        amount_input = await ainp(0, 0, f"{c['y']}Amount to decrypt: {c['r']}")
        amount_str = amount_input.strip()
        
        if not amount_str or not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            return
        
        amount = float(amount_str)
        if amount > max_decrypt:
            print(f"{c['R']}Amount too large (max: {max_decrypt:.6f}){c['r']}")
            await awaitkey()
            return
        
        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Decrypt {amount:.6f} oct? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return
        
        print(f"{c['B']}Enter number of retries for decryption (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        spin_task_dec = asyncio.create_task(spin_animation(0, 0, "Decrypting balance..."))
        
        ok, result = await decrypt_balance(amount, wallet_obj, retries=num_retries)
        
        spin_task_dec.cancel()
        try: await spin_task_dec
        except asyncio.CancelledError: pass
        print("")
        
        if ok:
            print(f"{c['g']}{c['B']}✓ Decryption submitted!{c['r']}")
            print(f"{c['g']}Tx hash: {result.get('tx_hash', 'unknown')}{c['r']}")
            print(f"{c['g']}Will process in next epoch{c['r']}")
            wallet_obj.last_update_time = 0
        else:
            print(f"{c['R']}{c['B']}✗ Error: {result.get('error', 'unknown')}{c['r']}")
        
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in decrypt_balance_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def private_transfer_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Private Transfer ({wallet_obj.name}){c['r']} ---\n")
        
        spin_task = asyncio.create_task(spin_animation(0, 0, "Checking encrypted balance..."))
        enc_data = await get_encrypted_balance(wallet_obj)
        spin_task.cancel()
        try: await spin_task
        except asyncio.CancelledError: pass
        print("")

        if not enc_data or enc_data['encrypted_raw'] == 0:
            print(f"{c['R']}No encrypted balance available.{c['r']}")
            print(f"{c['y']}Encrypt some balance first.{c['r']}")
            await awaitkey()
            return
        
        print(f"Encrypted Balance: {c['g']}{enc_data['encrypted']:.6f} oct{c['r']}\n")
        
        recipients_shuffled_for_run = await load_and_limit_recipients_from_file(prompt_limit=True)
        if recipients_shuffled_for_run is None:
            await awaitkey()
            return
        
        if not recipients_shuffled_for_run:
            print(f"{c['R']}No recipients selected for this run.{c['r']}")
            await awaitkey()
            return

        print(f"{c['g']}Selected {len(recipients_shuffled_for_run)} unique recipients for this run.{c['r']}")
        
        amount_input = await ainp(0, 0, f"\n{c['y']}Amount for EACH private transfer: {c['r']}")
        amount_str = amount_input.strip()
        
        if not amount_str or not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            return
        
        amount = float(amount_str)
        
        while True:
            times_input = await ainp(0, 0, f"\n{c['y']}How many times do you want to repeat this private transfer (1 for single run)?: {c['r']}")
            times_str = times_input.strip()
            if not times_str.isdigit() or int(times_str) <= 0:
                print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
            else:
                num_runs = int(times_str)
                break

        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between private transfers (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")

        while True:
            max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between private transfers (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")
        
        total_tx_per_run_base = len(recipients_shuffled_for_run)
        total_amount_needed = amount * total_tx_per_run_base * num_runs

        if amount > enc_data['encrypted']:
            print(f"{c['R']}Insufficient encrypted balance for a single transfer (needed: {amount:.6f}, available: {enc_data['encrypted']:.6f}){c['r']}")
            await awaitkey()
            return
        if total_amount_needed > enc_data['encrypted']:
            print(f"{c['R']}Insufficient encrypted balance for ALL transfers (needed: {total_amount_needed:.6f}, available: {enc_data['encrypted']:.6f}){c['r']}")
            await awaitkey()
            return

        print(f"\n--- {c['B']}Summary ({wallet_obj.name}) Private Multi-Transfer (Random Order){c['r']} ---")
        print(f"Sending {c['g']}{amount:.6f} OCT privately to {total_tx_per_run_base} addresses in random order.")
        print(f"Repeating this process {c['c']}{num_runs}{c['r']} time(s).")
        print(f"Total private transfers to attempt: {c['B']}{c['y']}{total_tx_per_run_base * num_runs}{c['r']}")
        print(f"Estimated total amount from encrypted balance: {c['B']}{c['g']}{total_amount_needed:.6f} OCT{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm this private multi-transfer operation? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        
        if confirm != 'y':
            return
        
        print(f"{c['B']}Enter number of retries for each transfer (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        overall_success_tx = 0
        overall_failed_tx = 0

        for run_idx in range(num_runs):
            print(f"{c['B']}--- Run {run_idx+1}/{num_runs} (Randomizing order) ---{c['r']}")
            recipients_current_run = recipients_shuffled_for_run[:]
            random.shuffle(recipients_current_run)

            for i, recipient_addr in enumerate(recipients_current_run):
                print(f"{c['c']}[{i+1}/{len(recipients_current_run)}] Creating private transfer of {amount:.6f} to {recipient_addr[:20]}...{c['r']}", end='', flush=True)

                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send private transfer to self.{c['r']}")
                    overall_failed_tx += 1
                    continue

                spin_task_transfer = asyncio.create_task(spin_animation(0, 0, ""))
                ok, result = await create_private_transfer(recipient_addr, amount, wallet_obj, retries=num_retries)
                
                spin_task_transfer.cancel()
                try: await spin_task_transfer
                except asyncio.CancelledError: pass
                print(f"\r{' ' * (len(f'[{i+1}/{len(recipients_current_run)}] Creating private transfer of {amount:.6f} to {recipient_addr[:20]}...') + 3)}", end='', flush=True)

                if ok:
                    overall_success_tx += 1
                    print(f"{c['g']}    ✓ Private transfer submitted!{c['r']}")
                    print(f"    {c['g']}Tx hash: {result.get('tx_hash', 'unknown')}{c['r']}")
                    print(f"    {c['g']}Recipient can claim in next epoch{c['r']}")
                else:
                    overall_failed_tx += 1
                    print(f"{c['R']}    ✗ Private transfer failed!{c['r']}")
                    print(f"    {c['R']}Error: {result.get('error', 'unknown')}{c['r']}")
                
                if i < len(recipients_current_run) - 1 or run_idx < num_runs - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}  Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)

        wallet_obj.last_update_time = 0
        print(f"\n--- {c['B']}Private Multi-Transfer Summary ({wallet_obj.name}){c['r']} ---")
        final_color = c['g'] if overall_failed_tx == 0 else c['R']
        print(f"{final_color}{c['B']}Completed: {overall_success_tx} successful, {overall_failed_tx} failed.{c['r']}")

        await awaitkey()

    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in private_transfer_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def claim_transfers_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Claim Private Transfers ({wallet_obj.name}){c['r']} ---\n")
        
        print(f"{c['c']}Loading pending transfers...{c['r']}")
        spin_task = asyncio.create_task(spin_animation(0, 0, ""))
        
        transfers = await get_pending_transfers(wallet_obj)
        spin_task.cancel()
        try: await spin_task
        except asyncio.CancelledError: pass
        print("")
        
        if not transfers:
            print(f"{c['y']}No pending transfers.{c['r']}")
            await awaitkey()
            return
        
        print(f"{c['B']}{c['g']}Found {len(transfers)} claimable transfers:{c['r']}\n")
        print(f"{c['c']}#   FROM                AMOUNT         EPOCH   ID{c['r']}")
        print(f"{c['w']}---------------------------------------------------------------{c['r']}")
        
        max_display = 10
        
        for i, t in enumerate(transfers[:max_display]):
            amount_str = "[encrypted]"
            amount_color = c['y']
            
            if t.get('encrypted_data') and t.get('ephemeral_key'):
                try:
                    shared = derive_shared_secret_for_claim(wallet_obj.priv, t['ephemeral_key'])
                    amt = decrypt_private_amount(t['encrypted_data'], shared)
                    if amt:
                        amount_str = f"{amt/μ:.6f} OCT"
                        amount_color = c['g']
                except:
                    pass
            
            print(f"{c['c']}[{i+1}]{c['r']} {c['w']}{t['sender'][:20]}...{c['r']} {amount_color}{amount_str:<14}{c['r']} {c['c']}ep{t.get('epoch_id', '?'):<8}{c['r']} {c['y']}#{t.get('id', '?')}{c['r']}")
        
        if len(transfers) > max_display:
            print(f"{c['y']}... and {len(transfers) - max_display} more{c['r']}")
        
        print(f"\n{c['w']}---------------------------------------------------------------{c['r']}")
        
        choice_input = await ainp(0, 0, f"{c['y']}Enter number to claim (0 to cancel): {c['r']}")
        choice = choice_input.strip()
        
        if not choice or choice == '0':
            return
        
        print(f"{c['B']}Enter number of retries for claiming (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(transfers):
                transfer = transfers[idx]
                transfer_id = transfer['id']
                
                print(f"{c['c']}Claiming transfer #{transfer_id}...{c['r']}")
                spin_task_claim = asyncio.create_task(spin_animation(0, 0, ""))
                
                ok, result = await claim_private_transfer(transfer_id, wallet_obj, retries=num_retries)
                
                spin_task_claim.cancel()
                try: await spin_task_claim
                except asyncio.CancelledError: pass
                print("")
                
                if ok:
                    print(f"{c['g']}{c['B']}✓ Claimed {result.get('amount', 'unknown')}! (Tx Hash: {result.get('tx_hash', 'unknown')[:10]}...){c['r']}")
                    print(f"  {c['c']}Explorer: {OCTRASCAN_TX_URL}{result.get('tx_hash', 'unknown')}{c['r']}\n")
                    print(f"{c['g']}Your encrypted balance has been updated{c['r']}")
                    wallet_obj.last_update_time = 0
                else:
                    error_msg = result.get('error', 'unknown error')
                    print(f"{c['R']}{c['B']}✗ Error: {error_msg}{c['r']}")
            else:
                print(f"{c['R']}Invalid selection{c['r']}")
        except ValueError:
            print(f"{c['R']}Invalid number{c['r']}")
        except Exception as e:
            print(f"{c['R']}An error occurred: {e}{c['r']}")
        
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in claim_transfers_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def exp_ui(wallet_obj):
    try:
        cls()
        print(f"\n--- {c['B']}Export Keys ({wallet_obj.name}){c['r']} ---\n")
        
        print(f"{c['c']}Current wallet info:{c['r']}\n")
        print(f"{c['c']}Address:{c['r']} {wallet_obj.addr}")
        print(f"{c['c']}Balance:{c['r']} ", end='')
        spin_task = asyncio.create_task(spin_animation(0, 0, "Fetching balance..."))
        n, b = await st(wallet_obj)
        spin_task.cancel()
        try: await spin_task
        except asyncio.CancelledError: pass
        print(f"{c['g']}{b:.6f} oct{c['r']}" if b is not None else f"{c['w']}---{c['r']}")
        print(f"{c['c']}RPC:{c['r']} {wallet_obj.rpc}\n")
        
        print(f"{c['y']}Export options:{c['r']}\n")
        print(f"{c['w']}[1] Show private key{c['r']}")
        print(f"{c['w']}[2] Save full wallet to file{c['r']}")
        print(f"{c['w']}[3] Copy address to clipboard{c['r']}")
        print(f"{c['w']}[0] Cancel{c['r']}\n")
        
        choice_input = await ainp(0, 0, f"{c['B']}{c['y']}Choice: {c['r']}")
        choice = choice_input.strip()
        
        print("")

        if choice == '1':
            print(f"{c['R']}PRIVATE KEY (KEEP SECRET!):{c['r']}")
            print(f"{c['R']}{wallet_obj.priv}{c['r']}\n")
            print(f"{c['g']}Public Key:{c['r']}")
            print(f"{c['g']}{wallet_obj.pub}{c['r']}")
            await awaitkey()
        
        elif choice == '2':
            fn = f"octra_wallet_export_{wallet_obj.name}_{int(time.time())}.json"
            wallet_data = {
                'priv': wallet_obj.priv,
                'addr': wallet_obj.addr,
                'rpc': wallet_obj.rpc,
                'name': wallet_obj.name
            }
            os.umask(0o077)

            try:
                with open(fn, 'w') as f:
                    json.dump(wallet_data, f, indent=2)
                os.chmod(fn, 0o600)
                print(f"{c['g']}Wallet saved to {fn}{c['r']}")
                print(f"{c['R']}WARNING: File contains private key - keep safe!{c['r']}")
            except Exception as e:
                print(f"{c['R']}Error saving wallet to file: {e}{c['r']}")
            await awaitkey()
            
        elif choice == '3':
            try:
                import pyperclip
                pyperclip.copy(wallet_obj.addr)
                print(f"{c['g']}Address copied to clipboard!{c['r']}")
            except ImportError:
                print(f"{c['R']}Error: pyperclip not installed. Please install it ('pip install pyperclip') to use this feature.{c['r']}")
            except Exception as e:
                print(f"{c['R']}Error copying to clipboard: {e}{c['r']}")
            await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in exp_ui: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def _run_daily_multi_send_for_wallet(wallet_obj, recipients_for_daily_run, amount_per_recipient, num_runs_per_wallet, min_delay, max_delay, results_queue_daily, num_retries=0):
    wallet_daily_success = 0
    wallet_daily_failed = 0
    try:
        print(f"\n{c['B']}  Starting Daily Run for Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")

        n, b = None, None
        for attempt in range(3):
            n, b = await st(wallet_obj)
            if n is not None and b is not None:
                break
            print(f"{c['y']}    Attempt {attempt+1}/3: Failed to get balance/nonce for {wallet_obj.name}. Retrying...{c['r']}")
            await asyncio.sleep(2)

        if n is None or b is None:
            print(f"{c['R']}    Failed to get balance/nonce after multiple attempts. Skipping wallet for this daily run.{c['r']}\n")
            await results_queue_daily.put(('fail_setup', wallet_obj.name, num_runs_per_wallet * len(recipients_for_daily_run)))
            return

        fee_per_tx = 0.001 if amount_per_recipient < 1000 else 0.003
        total_fees_per_run_wallet = fee_per_tx * len(recipients_for_daily_run)
        total_amount_needed_per_run_wallet = (amount_per_recipient * len(recipients_for_daily_run)) + total_fees_per_run_wallet

        if b < (total_amount_needed_per_run_wallet * num_runs_per_wallet):
            print(f"{c['R']}    Insufficient balance ({b:.6f}) for {num_runs_per_wallet} daily runs. Skipping wallet.{c['r']}\n")
            await results_queue_daily.put(('fail_balance', wallet_obj.name, num_runs_per_wallet * len(recipients_for_daily_run)))
            return

        print(f"    {c['c']}Current Balance:{c['r']} {c['g']}{b:.6f} oct{c['r']}")
        
        current_nonce = n + 1

        for daily_run_idx in range(num_runs_per_wallet):
            print(f"    {c['B']}--- Daily Sub-Run {daily_run_idx+1}/{num_runs_per_wallet} for {wallet_obj.name} (Randomizing order) ---{c['r']}")
            recipients_shuffled = recipients_for_daily_run[:]
            random.shuffle(recipients_shuffled)

            for i_recip, recipient_addr in enumerate(recipients_shuffled):
                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send to sender's own address ({recipient_addr[:20]}).{c['r']}")
                    wallet_daily_failed += 1
                    continue

                print(f"{c['c']}    [{i_recip+1}/{len(recipients_shuffled)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce}){c['r']}", end='', flush=True)
                t, _ = mk(recipient_addr, amount_per_recipient, current_nonce, wallet_obj)
                ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)

                print(f"\r{' ' * (len(f'    [{i_recip+1}/{len(recipients_shuffled)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce})') + 3)}", end='', flush=True)

                if ok:
                    wallet_daily_success += 1
                    print(f"{c['g']}      ✓ Accepted! Hash: {hs[:10]}... Time: {dt:.2f}s{c['r']}")
                    wallet_obj.history.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': DAILY_AMOUNT_PER_RECIPIENT,
                        'to': recipient_addr,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    wallet_daily_failed += 1
                    print(f"{c['R']}      ✗ Failed! Error: {str(hs)[:70]}{c['r']}")
                current_nonce += 1

                if i_recip < len(recipients_shuffled) - 1 or daily_run_idx < num_runs_per_wallet - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}      Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)

            wallet_obj.last_update_time = 0

        print(f"\n{c['c']}    Wallet Daily Summary: {wallet_daily_success} success, {wallet_daily_failed} failed.{c['r']}\n")
        await results_queue_daily.put(('done', wallet_obj.name, wallet_daily_success, wallet_daily_failed))

    except Exception as wallet_daily_e:
        print(f"{c['R']}  Wallet '{wallet_obj.name}' daily run failed due to error: {wallet_daily_e}{c['r']}\n")
        await results_queue_daily.put(('fail_exception', wallet_obj.name, num_runs_per_wallet * len(recipients_for_daily_run)))

async def _run_daily_multi_send_single_wallet(wallet_obj, recipients_for_daily_run, amount_per_recipient, num_runs_per_wallet, min_delay, max_delay, num_retries=0):
    wallet_daily_success = 0
    wallet_daily_failed = 0
    try:
        print(f"\n{c['B']}  Starting Daily Run for SELECTED Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")

        n, b = None, None
        for attempt in range(3):
            n, b = await st(wallet_obj)
            if n is not None and b is not None:
                break
            print(f"{c['y']}    Attempt {attempt+1}/3: Failed to get balance/nonce. Retrying...{c['r']}")
            await asyncio.sleep(2)

        if n is None or b is None:
            print(f"{c['R']}    Failed to get balance/nonce after multiple attempts. Skipping this daily run.{c['r']}\n")
            return (0, num_runs_per_wallet * len(recipients_for_daily_run))
        
        fee_per_tx = 0.001 if amount_per_recipient < 1000 else 0.003
        total_fees_per_run_wallet = fee_per_tx * len(recipients_for_daily_run)
        total_amount_needed_per_run_wallet = (amount_per_recipient * len(recipients_for_daily_run)) + total_fees_per_run_wallet

        if b < (total_amount_needed_per_run_wallet * num_runs_per_wallet):
            print(f"{c['R']}    Insufficient balance ({b:.6f}) for {num_runs_per_wallet} daily runs. Skipping.{c['r']}\n")
            return (0, num_runs_per_wallet * len(recipients_for_daily_run))

        print(f"    {c['c']}Current Balance:{c['r']} {c['g']}{b:.6f} oct{c['r']}")
        
        current_nonce = n + 1

        for daily_run_idx in range(num_runs_per_wallet):
            print(f"    {c['B']}--- Daily Sub-Run {daily_run_idx+1}/{num_runs_per_wallet} for {wallet_obj.name} (Randomizing order) ---{c['r']}")
            recipients_shuffled = recipients_for_daily_run[:]
            random.shuffle(recipients_shuffled)

            for i_recip, recipient_addr in enumerate(recipients_shuffled):
                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send to sender's own address ({recipient_addr[:20]}).{c['r']}")
                    wallet_daily_failed += 1
                    continue

                print(f"{c['c']}    [{i_recip+1}/{len(recipients_shuffled)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce}){c['r']}", end='', flush=True)
                t, _ = mk(recipient_addr, amount_per_recipient, current_nonce, wallet_obj)
                ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)

                print(f"\r{' ' * (len(f'    [{i_recip+1}/{len(recipients_shuffled)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce})') + 3)}", end='', flush=True)

                if ok:
                    wallet_daily_success += 1
                    print(f"{c['g']}      ✓ Accepted! Hash: {hs[:10]}... Time: {dt:.2f}s{c['r']}")
                    wallet_obj.history.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': DAILY_AMOUNT_PER_RECIPIENT,
                        'to': recipient_addr,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    wallet_daily_failed += 1
                    print(f"{c['R']}      ✗ Failed! Error: {str(hs)[:70]}{c['r']}")
                current_nonce += 1

                if i_recip < len(recipients_shuffled) - 1 or daily_run_idx < num_runs_per_wallet - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}      Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)

            wallet_obj.last_update_time = 0

        print(f"\n{c['c']}    Wallet Daily Summary: {wallet_daily_success} success, {wallet_daily_failed} failed.{c['r']}\n")
        return (wallet_daily_success, wallet_daily_failed)

    except Exception as e:
        print(f"{c['R']}  Wallet '{wallet_obj.name}' daily run failed due to error: {e}{c['r']}\n")
        traceback.print_exc()
        return (0, num_runs_per_wallet * len(recipients_for_daily_run))

async def _run_single_wallet_multi_send_concurrent(wallet_obj, recipients_shuffled_for_run, amount_per_recipient, num_runs, min_delay, max_delay, num_retries, results_queue):
    wallet_success_count = 0
    wallet_fail_count = 0
    try:
        print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")

        n, b = await st(wallet_obj)
        if n is None:
            print(f"{c['R']}{c['B']}    Failed to get nonce! Skipping wallet.{c['r']}\n")
            await results_queue.put(('fail_nonce', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))
            return

        fee_per_tx = 0.001 if amount_per_recipient < 1000 else 0.003
        total_amount_needed_per_run = (amount_per_recipient * len(recipients_shuffled_for_run)) + (fee_per_tx * len(recipients_shuffled_for_run))
        total_required_for_this_wallet = total_amount_needed_per_run * num_runs

        if b is None or b < total_required_for_this_wallet:
            print(f"{c['R']}{c['B']}    Insufficient balance ({b:.6f} < {total_required_for_this_wallet:.6f})! Skipping wallet.{c['r']}\n")
            await results_queue.put(('fail_balance', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))
            return

        print(f"    {c['c']}Current Balance:{c['r']} {c['g']}{b:.6f} oct{c['r']}")
        print(f"    {c['c']}Next Nonce:{c['r']}   {c['y']}{n + 1}{c['r']}")
        print(f"    {c['c']}Attempting {len(recipients_shuffled_for_run)} transactions, {num_runs} times from this wallet...{c['r']}")

        current_nonce_loop = n + 1

        for run_idx in range(num_runs):
            print(f"    {c['B']}--- Run {run_idx+1}/{num_runs} for {wallet_obj.name} (Randomizing order) ---{c['r']}")
            recipients_current_run = recipients_shuffled_for_run[:]
            random.shuffle(recipients_current_run)

            for i_recip, recipient_addr in enumerate(recipients_current_run):
                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send to sender's own address ({recipient_addr[:20]}).{c['r']}")
                    wallet_fail_count += 1
                    continue

                print(f"{c['c']}    [{i_recip+1}/{len(recipients_current_run)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce_loop}){c['r']}", end='', flush=True)
                t, _ = mk(recipient_addr, amount_per_recipient, current_nonce_loop, wallet_obj)
                ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)

                print(f"\r{' ' * (len(f'    [{i_recip+1}/{len(recipients_current_run)}] Sending {amount_per_recipient:.6f} to {recipient_addr[:20]}... (Nonce: {current_nonce_loop})') + 3)}", end='', flush=True)

                if ok:
                    wallet_success_count += 1
                    print(f"{c['g']}      ✓ Accepted! Hash: {hs[:10]}... Time: {dt:.2f}s{c['r']}")
                    wallet_obj.history.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': amount_per_recipient,
                        'to': recipient_addr,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    wallet_fail_count += 1
                    print(f"{c['R']}      ✗ Failed! Error: {str(hs)[:70]}{c['r']}")
                current_nonce_loop += 1

                if i_recip < len(recipients_current_run) - 1 or run_idx < num_runs - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}      Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)

            print(f"\n{c['c']}    Run Summary for {wallet_obj.name}: {wallet_success_count} success, {wallet_fail_count} failed.{c['r']}\n")
            await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

    except Exception as wallet_e:
        print(f"{c['R']}    Wallet '{wallet_obj.name}' multi-send failed due to error: {wallet_e}{c['r']}\n")
        await results_queue.put(('fail_exception', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))

async def _run_single_wallet_private_transfer_concurrent(wallet_obj, recipients_shuffled_for_run, amount_per_wallet, num_runs, min_delay, max_delay, num_retries, results_queue):
    wallet_success_count = 0
    wallet_fail_count = 0
    try:
        print(f"\n{c['B']}  Starting Private Transfer for Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")

        enc_data = await get_encrypted_balance(wallet_obj, retries=num_retries)
        if not enc_data or enc_data['encrypted_raw'] == 0:
            print(f"{c['R']}{c['B']}    No encrypted balance available or cannot get info. Skipping wallet.{c['r']}\n")
            await results_queue.put(('fail_info', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))
            return

        total_amount_needed_for_this_wallet = amount_per_wallet * num_runs * len(recipients_shuffled_for_run)
        if total_amount_needed_for_this_wallet > enc_data['encrypted']:
            print(f"{c['R']}{c['B']}    Insufficient encrypted balance ({enc_data['encrypted']:.6f}) for all transfers ({total_amount_needed_for_this_wallet:.6f})! Skipping wallet.{c['r']}\n")
            await results_queue.put(('fail_balance', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))
            return

        print(f"    {c['c']}Encrypted Balance:{c['r']} {c['g']}{enc_data['encrypted']:.6f} oct{c['r']}")
        print(f"    {c['c']}Attempting {num_runs * len(recipients_shuffled_for_run)} private transfers from this wallet...{c['r']}")

        for run_idx in range(num_runs):
            print(f"    {c['B']}--- Run {run_idx+1}/{num_runs} for {wallet_obj.name} (Randomizing order) ---{c['r']}")
            recipients_current_run = recipients_shuffled_for_run[:]
            random.shuffle(recipients_current_run)

            for i_recip, recipient_addr in enumerate(recipients_current_run):
                if recipient_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send private transfer to self.{c['r']}")
                    wallet_fail_count += 1
                    continue

                print(f"{c['c']}    [{i_recip+1}/{len(recipients_current_run)}] Creating private transfer of {amount_per_wallet:.6f} to {recipient_addr[:20]}...{c['r']}", end='', flush=True)

                spin_task_transfer = asyncio.create_task(spin_animation(0, 0, ""))
                private_transfer_ok, private_transfer_result = await create_private_transfer(recipient_addr, amount_per_wallet, wallet_obj, retries=num_retries)
                spin_task_transfer.cancel()
                try: await spin_task_transfer
                except asyncio.CancelledError: pass
                print(f"\r{' ' * (len(f'    [{i_recip+1}/{len(recipients_current_run)}] Creating private transfer of {amount_per_wallet:.6f} to {recipient_addr[:20]}...') + 3)}", end='', flush=True)

                if private_transfer_ok:
                    wallet_success_count += 1
                    print(f"{c['g']}      ✓ Private transfer submitted!{c['r']}")
                    print(f"      {c['g']}Tx hash: {private_transfer_result.get('tx_hash', 'unknown')}{c['r']}")
                    print(f"      {c['g']}Recipient can claim in next epoch{c['r']}")
                else:
                    wallet_fail_count += 1
                    print(f"{c['R']}      ✗ Private transfer failed!{c['r']}")
                    print(f"      {c['R']}Error: {private_transfer_result.get('error', 'unknown')}{c['r']}")

                if i_recip < len(recipients_current_run) - 1 or run_idx < num_runs - 1:
                    delay_sec = random.uniform(min_delay, max_delay)
                    print(f"{c['c']}      Delaying for {delay_sec:.1f} seconds...{c['r']}")
                    await asyncio.sleep(delay_sec)

        wallet_obj.last_update_time = 0
        print(f"\n{c['c']}    Wallet Private Transfer Summary: {wallet_success_count} success, {wallet_fail_count} failed.{c['r']}\n")
        await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

    except Exception as wallet_e:
        print(f"{c['R']}  Wallet '{wallet_obj.name}' private transfer failed due to error: {wallet_e}{c['r']}\n")
        await results_queue.put(('fail_exception', wallet_obj.name, num_runs * len(recipients_shuffled_for_run)))

async def send_transaction_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Send Transaction (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to send from ALL loaded wallets!{c['r']}\n")

        to_addr = await get_recipient_address_from_user(
            allow_random_from_file=True,
            prompt_text="Enter RECIPIENT address for ALL transactions:"
        )
        to_addr = to_addr.strip()
        if not to_addr or to_addr.lower() == 'esc':
            return

        if not b58.match(to_addr):
            print(f"{c['R']}{c['B']}Invalid recipient address!{c['r']}")
            await awaitkey()
            return

        amount_input = await ainp(0, 0, f"\n{c['y']}Enter AMOUNT per transaction (e.g., 0.01) for EACH wallet: {c['r']}")
        amount_str = amount_input.strip()
        if not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        a_per_wallet = float(amount_str)

        msg_input = await ainp(0, 0, f"\n{c['y']}Message (optional, max 1024, or Enter to skip) for ALL transactions: {c['r']}")
        msg = msg_input.strip()
        if not msg:
            msg = None
        elif len(msg) > 1024:
            msg = msg[:1024]
            print(f"{c['y']}Message truncated to 1024 chars{c['r']}")
        
        while True:
            times_input = await ainp(0, 0, f"\n{c['y']}How many times to repeat this for EACH wallet (1 for single send)?: {c['r']}")
            times_str = times_input.strip()
            if not times_str.isdigit() or int(times_str) <= 0:
                print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
            else:
                num_times_per_wallet = int(times_str)
                break
        
        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between transactions (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
        
        while True:
            max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between transactions (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

        print(f"\n--- {c['B']}Summary (All Wallets){c['r']} ---")
        print(f"Recipient for all: {c['g']}{to_addr}{c['r']}")
        print(f"Amount per wallet: {c['g']}{a_per_wallet:.6f} oct{c['r']}")
        if msg:
            print(f"Message for all: {c['c']}{msg[:50]}{'...' if len(msg) > 50 else ''}{c['r']}")
        print(f"Repeat {c['c']}{num_times_per_wallet}{c['r']} time(s) per wallet. Delay: {c['c']}{min_delay:.1f}-{max_delay:.1f}s{c['r']}")
        
        total_tx_attempted_overall = len(wallets_available) * num_times_per_wallet
        print(f"Total transactions attempted overall: {c['B']}{c['y']}{total_tx_attempted_overall}{c['r']}")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm sending {num_times_per_wallet} times from EACH wallet to {to_addr}? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each transaction (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Transactions from All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        async def _run_single_wallet_send_concurrent(wallet_obj, to_addr, a_per_wallet, msg, num_times_per_wallet, min_delay, max_delay, num_retries, results_queue):
            wallet_success_count = 0
            wallet_fail_count = 0
            try:
                print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")
                
                if to_addr == wallet_obj.addr:
                    print(f"{c['y']}    Skipping: Cannot send to sender's own address. Use encrypt/decrypt for internal changes.{c['r']}\n")
                    await results_queue.put(('skip', wallet_obj.name, num_times_per_wallet))
                    return

                n, b = await st(wallet_obj)
                if n is None:
                    print(f"{c['R']}{c['B']}    Failed to get nonce! Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_nonce', wallet_obj.name, num_times_per_wallet))
                    return
                
                fee = 0.001 if a_per_wallet < 1000 else 0.003
                required_balance_per_tx = a_per_wallet + fee
                total_required_for_this_wallet = required_balance_per_tx * num_times_per_wallet

                if b is None or b < total_required_for_this_wallet:
                    print(f"{c['R']}{c['B']}    Insufficient balance ({b:.6f} < {total_required_for_this_wallet:.6f})! Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_balance', wallet_obj.name, num_times_per_wallet))
                    return
                
                print(f"    {c['c']}Current Balance:{c['r']} {c['g']}{b:.6f} oct{c['r']}")
                print(f"    {c['c']}Next Nonce:{c['r']}   {c['y']}{n + 1}{c['r']}")
                print(f"    {c['c']}Attempting {num_times_per_wallet} sends from this wallet...{c['r']}")

                current_nonce_loop = n + 1

                for j in range(num_times_per_wallet):
                    print(f"{c['c']}    [{j+1}/{num_times_per_wallet}] Sending {a_per_wallet:.6f} oct (Nonce: {current_nonce_loop}){c['r']}", end='', flush=True)
                    
                    t, _ = mk(to_addr, a_per_wallet, current_nonce_loop, wallet_obj, msg)
                    ok, hs, dt, r = await snd(t, wallet_obj, retries=num_retries)

                    print(f"\r{' ' * (len(f'    [{j+1}/{num_times_per_wallet}] Sending {a_per_wallet:.6f} oct (Nonce: {current_nonce_loop})') + 3)}", end='', flush=True)

                    if ok:
                        wallet_success_count += 1
                        print(f"{c['g']}      ✓ Accepted! Hash: {hs}{c['r']}")
                        print(f"      {c['w']}Time: {dt:.2f}s{c['r']}")
                        if r and 'pool_info' in r:
                            print(f"      {c['y']}Pool: {r['pool_info'].get('total_pool_size', 0)} txs pending{c['r']}")
                        print(f"      {c['c']}Explorer: {OCTRASCAN_TX_URL}{hs}{c['r']}\n")
                        
                        wallet_obj.history.append({
                            'time': datetime.now(),
                            'hash': hs,
                            'amt': a_per_wallet,
                            'to': to_addr,
                            'type': 'out',
                            'ok': True,
                            'msg': msg
                        })
                    else:
                        wallet_fail_count += 1
                        print(f"{c['R']}      ✗ Failed! Error: {str(hs)}{c['r']}\n")
            
                    current_nonce_loop += 1
                    if j < num_times_per_wallet - 1:
                        delay_sec = random.uniform(min_delay, max_delay)
                        print(f"{c['c']}      Delaying for {delay_sec:.1f} seconds...{c['r']}")
                        await asyncio.sleep(delay_sec)
                
                print(f"\n{c['c']}  Wallet Summary: {wallet_success_count} success, {wallet_fail_count} failed.{c['r']}\n")
                await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

            except Exception as wallet_e:
                print(f"{c['R']}  Wallet '{wallet_obj.name}' failed due to error: {wallet_e}{c['r']}\n")
                await results_queue.put(('fail_exception', wallet_obj.name, num_times_per_wallet))

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_send_concurrent(wallet_obj, to_addr, a_per_wallet, msg, num_times_per_wallet, min_delay, max_delay, num_retries, results_queue))

        await asyncio.gather(*tasks, return_exceptions=True)

        success_count_overall = 0
        fail_count_overall = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                success_count_overall += counts[0]
                fail_count_overall += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                fail_count_overall += counts[0]

        print(f"\n--- {c['B']}All Wallets Transaction Summary{c['r']} ---")
        final_color = c['g'] if fail_count_overall == 0 else c['R']
        print(f"{final_color}{c['B']}Total transactions: {success_count_overall} successful, {fail_count_overall} failed.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in send_transaction_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def multi_send_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Multi Send to Randomly Ordered Recipients (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to send from EACH loaded wallet to ALL recipients in a random order!{c['r']}\n")

        recipients_shuffled_for_run = await load_and_limit_recipients_from_file(prompt_limit=True)
        if recipients_shuffled_for_run is None:
            await awaitkey()
            return
        
        if not recipients_shuffled_for_run:
            print(f"{c['R']}No recipients selected for this run.{c['r']}")
            await awaitkey()
            return

        print(f"{c['g']}Selected {len(recipients_shuffled_for_run)} unique recipients for this run.{c['r']}")
        
        amount_input = await ainp(0, 0, f"\n{c['y']}Enter amount for EACH recipient (e.g., 0.1): {c['r']}")
        amount_str = amount_input.strip()
        if not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        a = float(amount_str)
        
        global DAILY_MODE_ACTIVE, DAILY_RUNS_PER_WALLET_PER_DAY, DAILY_AMOUNT_PER_RECIPIENT, DAILY_MIN_DELAY, DAILY_MAX_DELAY, DAILY_RECIPIENT_LIMIT, DAILY_MODE_TARGET_WALLET, DAILY_MODE_RETRIES
        
        daily_choice = await ainp(0, 0, f"\n{c['B']}{c['y']}Do you want to run this Multi Send daily (every {DAILY_INTERVAL_HOURS} hours)? [y/n]: {c['r']}")
        if daily_choice.strip().lower() == 'y':
            DAILY_MODE_ACTIVE = True
            DAILY_MODE_TARGET_WALLET = None
            
            while True:
                runs_input = await ainp(0, 0, f"{c['y']}How many times do you want to repeat Multi Send (1 for single run) PER DAY for EACH wallet?: {c['r']}")
                if runs_input.strip().isdigit() and int(runs_input.strip()) > 0:
                    DAILY_RUNS_PER_WALLET_PER_DAY = int(runs_input.strip())
                    break
                else:
                    print(f"{c['R']}{c['B']}Invalid input. Please enter a positive integer.{c['r']}")
            
            DAILY_AMOUNT_PER_RECIPIENT = a
            DAILY_RECIPIENT_LIMIT = len(recipients_shuffled_for_run)
            
            while True:
                min_delay_input = await ainp(0, 0, f"{c['y']}Minimum delay between transactions (seconds) for daily runs?: {c['r']}")
                try:
                    min_delay_val = float(min_delay_input.strip())
                    if min_delay_val < 0: raise ValueError
                    DAILY_MIN_DELAY = min_delay_val
                    break
                except ValueError:
                    print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
            
            while True:
                max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between transactions (seconds) for daily runs?: {c['r']}")
                try:
                    max_delay_val = float(max_delay_input.strip())
                    if max_delay_val < DAILY_MIN_DELAY: raise ValueError
                    DAILY_MAX_DELAY = max_delay_val
                    break
                except ValueError:
                    print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

            print(f"{c['B']}Enter number of retries for each transaction in daily mode (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
            retries_input = await ainp(0,0, '')
            try:
                DAILY_MODE_RETRIES = int(retries_input.strip())
                if DAILY_MODE_RETRIES < 0: raise ValueError
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
                DAILY_MODE_RETRIES = 0

            print(f"{c['g']}Daily Multi Send configured! Script will now run in automated daily mode.{c['r']}")
            print(f"{c['y']}To stop, press Ctrl+C.{c['r']}")
            await awaitkey()
            return
        else:
            while True:
                times_input = await ainp(0, 0, f"\n{c['y']}How many times do you want to repeat this entire multi-send (1 for single run)?: {c['r']}")
                times_str = times_input.strip()
                if not times_str.isdigit() or int(times_str) <= 0:
                    print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
                else:
                    num_runs = int(times_str)
                    break

        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between transactions (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")
        
        while True:
            max_delay_input = await ainp(0, 0, f"\n{c['y']}Maximum delay between transactions (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")

        total_tx_per_run_base = len(recipients_shuffled_for_run)
        fee_per_tx = 0.001 if a < 1000 else 0.003
        total_fees_per_run_base = fee_per_tx * total_tx_per_run_base
        total_amount_needed_per_run_base = (a * total_tx_per_run_base) + total_fees_per_run_base

        overall_total_transactions = total_tx_per_run_base * num_runs
        overall_total_cost = total_amount_needed_per_run_base * num_runs

        print(f"\n--- {c['B']}Summary (All Wallets Multi Send Random Order){c['r']} ---")
        print(f"Sending {c['g']}{a:.6f} OCT{c['r']} to {total_tx_per_run_base} addresses in random order from EACH wallet.")
        print(f"Repeating this process {c['c']}{num_runs}{c['r']} time(s).")
        print(f"Delay between transactions: {c['c']}{min_delay:.1f}-{max_delay:.1f} seconds{c['r']}")
        print(f"Total transactions to attempt across all wallets: {c['B']}{c['y']}{overall_total_transactions}{c['r']}")
        print(f"Estimated total cost (including fees): {c['B']}{c['g']}{overall_total_cost:.6f} OCT{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm this multi-send operation? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each transaction (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Multi-Send from All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_multi_send_concurrent(
                wallet_obj, recipients_shuffled_for_run, a, num_runs, min_delay, max_delay, num_retries, results_queue
            ))

        await asyncio.gather(*tasks, return_exceptions=True)

        overall_success_tx = 0
        overall_failed_tx = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                overall_success_tx += counts[0]
                overall_failed_tx += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                overall_failed_tx += counts[0]

        print(f"\n--- {c['B']}Overall Multi-Send Summary (All Wallets){c['r']} ---")
        final_color = c['g'] if overall_failed_tx == 0 else c['R']
        print(f"{final_color}{c['B']}Total transactions: {overall_success_tx} successful, {overall_failed_tx} failed.{c['r']}")

        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in multi_send_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def encrypt_balance_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Encrypt Balance (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to encrypt balance from ALL loaded wallets!{c['r']}\n")

        amount_input = await ainp(0, 0, f"\n{c['y']}Enter AMOUNT to encrypt per wallet (e.g., 0.1): {c['r']}")
        amount_str = amount_input.strip()
        if not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        amount_per_wallet = float(amount_str)

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm encrypting {amount_per_wallet:.6f} OCT from EACH wallet? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each encryption (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Encryption from All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        async def _run_single_wallet_encrypt_concurrent(wallet_obj, amount_per_wallet, results_queue, num_retries):
            wallet_success_count = 0
            wallet_fail_count = 0
            try:
                print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")
                
                _, pub_bal = await st(wallet_obj)
                enc_data = await get_encrypted_balance(wallet_obj, retries=num_retries)
                if not enc_data:
                    print(f"{c['R']}{c['B']}    Cannot get encrypted balance info. Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_info', wallet_obj.name, 1))
                    return
                
                max_encrypt = enc_data['public_raw'] / μ - (0.001 if enc_data['public_raw'] / μ > 0.001 else 0)
                if max_encrypt <= 0 or amount_per_wallet > max_encrypt:
                    print(f"{c['R']}{c['B']}    Insufficient public balance ({pub_bal:.6f}) or amount too large (max {max_encrypt:.6f}). Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_balance', wallet_obj.name, 1))
                    return
                
                print(f"    {c['c']}Public Balance:{c['r']} {c['w']}{pub_bal:.6f} oct{c['r']}")
                print(f"    {c['c']}Encrypted Balance:{c['r']} {c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
                
                spin_task_enc = asyncio.create_task(spin_animation(0, 0, "    Encrypting balance..."))
                ok, result = await encrypt_balance(amount_per_wallet, wallet_obj, retries=num_retries)
                
                spin_task_enc.cancel()
                try: await spin_task_enc
                except asyncio.CancelledError: pass
                print("")

                if ok:
                    wallet_success_count += 1
                    print(f"{c['g']}{c['B']}✓ Encryption submitted!{c['r']}")
                    print(f"{c['g']}Tx hash: {result.get('tx_hash', 'unknown')}{c['r']}\n")
                    wallet_obj.last_update_time = 0
                else:
                    wallet_fail_count += 1
                    print(f"{c['R']}{c['B']}    ✗ Error: {result.get('error', 'unknown')}{c['r']}\n")
                
                await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

            except Exception as wallet_e:
                print(f"{c['R']}  Wallet '{wallet_obj.name}' encryption failed due to error: {wallet_e}{c['r']}\n")
                await results_queue.put(('fail_exception', wallet_obj.name, 1))

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_encrypt_concurrent(wallet_obj, amount_per_wallet, results_queue, num_retries))

        await asyncio.gather(*tasks, return_exceptions=True)

        success_count_overall = 0
        fail_count_overall = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                success_count_overall += counts[0]
                fail_count_overall += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                fail_count_overall += counts[0]

        print(f"\n--- {c['B']}All Wallets Encryption Summary{c['r']} ---")
        final_color = c['g'] if fail_count_overall == 0 else c['R']
        print(f"{final_color}{c['B']}Total: {success_count_overall} successful, {fail_count_overall} failed.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in encrypt_balance_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def decrypt_balance_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Decrypt Balance (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to decrypt balance from ALL loaded wallets!{c['r']}\n")

        amount_input = await ainp(0, 0, f"\n{c['y']}Enter AMOUNT to decrypt per wallet (e.g., 0.1): {c['r']}")
        amount_str = amount_input.strip()
        if not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            print(f"{c['R']}{c['B']}Invalid amount!{c['r']}")
            await awaitkey()
            return
        amount_per_wallet = float(amount_str)

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm decrypting {amount_per_wallet:.6f} OCT from EACH wallet? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each decryption (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Decryption from All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        async def _run_single_wallet_decrypt_concurrent(wallet_obj, amount_per_wallet, results_queue, num_retries):
            wallet_success_count = 0
            wallet_fail_count = 0
            try:
                print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")
                
                _, pub_bal = await st(wallet_obj)
                enc_data = await get_encrypted_balance(wallet_obj, retries=num_retries)
                if not enc_data or enc_data['encrypted_raw'] == 0:
                    print(f"{c['R']}{c['B']}    No encrypted balance available or cannot get info. Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_info', wallet_obj.name, 1))
                    return
                
                max_decrypt = enc_data['encrypted_raw'] / μ
                if amount_per_wallet > max_decrypt:
                    print(f"{c['R']}{c['B']}    Insufficient encrypted balance ({enc_data['encrypted']:.6f}) or amount too large (max {max_decrypt:.6f}). Skipping wallet.{c['r']}\n")
                    await results_queue.put(('fail_balance', wallet_obj.name, 1))
                    return
                
                print(f"    {c['c']}Public Balance:{c['r']} {c['w']}{pub_bal:.6f} oct{c['r']}")
                print(f"    {c['c']}Encrypted Balance:{c['r']} {c['y']}{enc_data['encrypted']:.6f} oct{c['r']}")
                
                spin_task_dec = asyncio.create_task(spin_animation(0, 0, "    Decrypting balance..."))
                ok, result = await decrypt_balance(amount_per_wallet, wallet_obj, retries=num_retries)
                
                spin_task_dec.cancel()
                try: await spin_task_dec
                except asyncio.CancelledError: pass
                print("")

                if ok:
                    wallet_success_count += 1
                    print(f"{c['g']}{c['B']}✓ Decryption submitted!{c['r']}")
                    print(f"{c['g']}Tx hash: {result.get('tx_hash', 'unknown')}{c['r']}\n")
                    wallet_obj.last_update_time = 0
                else:
                    wallet_fail_count += 1
                    print(f"{c['R']}{c['B']}    ✗ Error: {result.get('error', 'unknown')}{c['r']}\n")
                
                await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

            except Exception as wallet_e:
                print(f"{c['R']}  Wallet '{wallet_obj.name}' decryption failed due to error: {wallet_e}{c['r']}\n")
                await results_queue.put(('fail_exception', wallet_obj.name, 1))

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_decrypt_concurrent(wallet_obj, amount_per_wallet, results_queue, num_retries))

        await asyncio.gather(*tasks, return_exceptions=True)

        success_count_overall = 0
        fail_count_overall = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                success_count_overall += counts[0]
                fail_count_overall += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                fail_count_overall += counts[0]

        print(f"\n--- {c['B']}All Wallets Decryption Summary{c['r']} ---")
        final_color = c['g'] if fail_count_overall == 0 else c['R']
        print(f"{final_color}{c['B']}Total: {success_count_overall} successful, {fail_count_overall} failed.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in decrypt_balance_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def private_transfer_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Private Transfer (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to create private transfers from ALL loaded wallets!{c['r']}\n")

        recipients_shuffled_for_run = await load_and_limit_recipients_from_file(prompt_limit=True)
        if recipients_shuffled_for_run is None:
            await awaitkey()
            return
        
        if not recipients_shuffled_for_run:
            print(f"{c['R']}No recipients selected for this run.{c['r']}")
            await awaitkey()
            return

        print(f"{c['g']}Selected {len(recipients_shuffled_for_run)} unique recipients for this run.{c['r']}")
        
        amount_input = await ainp(0, 0, f"\n{c['y']}Amount for EACH private transfer: {c['r']}")
        amount_str = amount_input.strip()
        
        if not amount_str or not re.match(r"^\d+(\.\d+)?$", amount_str) or float(amount_str) <= 0:
            return
        
        amount_per_wallet = float(amount_str)
        
        while True:
            times_input = await ainp(0, 0, f"\n{c['y']}How many times do you want to repeat this private transfer (1 for single run) PER WALLET?: {c['r']}")
            times_str = times_input.strip()
            if not times_str.isdigit() or int(times_str) <= 0:
                print(f"{c['R']}{c['B']}Invalid number of times. Please enter a positive integer.{c['r']}")
            else:
                num_runs = int(times_str)
                break

        while True:
            min_delay_input = await ainp(0, 0, f"\n{c['y']}Minimum delay between private transfers (seconds)?: {c['r']}")
            try:
                min_delay = float(min_delay_input.strip())
                if min_delay < 0: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid minimum delay. Please enter a non-negative number.{c['r']}")

        while True:
            max_delay_input = await ainp(0, 0, f"{c['y']}Maximum delay between private transfers (seconds)?: {c['r']}")
            try:
                max_delay = float(max_delay_input.strip())
                if max_delay < min_delay: raise ValueError
                break
            except ValueError:
                print(f"{c['R']}{c['B']}Invalid maximum delay. Must be >= minimum delay.{c['r']}")
        
        total_tx_per_run_base = len(recipients_shuffled_for_run)
        overall_total_transactions = len(wallets_available) * total_tx_per_run_base * num_runs
        overall_total_cost = amount_per_wallet * overall_total_transactions

        print(f"\n--- {c['B']}Summary (All Wallets Private Multi-Transfer Random Order){c['r']} ---")
        print(f"Sending {c['g']}{amount_per_wallet:.6f} OCT privately to {total_tx_per_run_base} addresses in random order from EACH wallet.")
        print(f"Repeating this process {c['c']}{num_runs}{c['r']} time(s).")
        print(f"Total private transfers to attempt across all wallets: {c['B']}{c['y']}{overall_total_transactions}{c['r']}")
        print(f"Estimated total amount from encrypted balance: {c['B']}{c['g']}{overall_total_cost:.6f} OCT{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm this private multi-transfer operation? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each transfer (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Private Transfers from All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_private_transfer_concurrent(
                wallet_obj, recipients_shuffled_for_run, amount_per_wallet, num_runs, min_delay, max_delay, num_retries, results_queue
            ))

        await asyncio.gather(*tasks, return_exceptions=True)

        overall_success_tx = 0
        overall_failed_tx = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                overall_success_tx += counts[0]
                overall_failed_tx += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                overall_failed_tx += counts[0]

        print(f"\n--- {c['B']}All Wallets Private Transfer Summary{c['r']} ---")
        final_color = c['g'] if overall_failed_tx == 0 else c['R']
        print(f"{final_color}{c['B']}Total: {overall_success_tx} successful, {overall_failed_tx} failed.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in private_transfer_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def claim_transfers_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Claim Private Transfers (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will attempt to claim all pending private transfers for ALL loaded wallets!{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm claiming all pending transfers for EACH wallet? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"{c['B']}Enter number of retries for each claim (0 for no retry - if tx fails, it will not be re-attempted): {c['r']}", end='', flush=True)
        retries_input = await ainp(0,0, '')
        try:
            num_retries = int(retries_input.strip())
            if num_retries < 0: raise ValueError
        except ValueError:
            print(f"{c['R']}{c['B']}Invalid retry count. Setting to 0.{c['r']}")
            num_retries = 0

        print(f"\n--- {c['B']}Initiating Claim from All Wallets (Concurrent)...{c['r']} ---\n")
        
        overall_success_wallets = 0
        overall_failed_wallets = 0

        tasks = []
        results_queue = asyncio.Queue()

        async def _run_single_wallet_claim_concurrent(wallet_obj, results_queue, num_retries):
            wallet_success_count = 0
            wallet_fail_count = 0
            try:
                print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")
                
                print(f"{c['c']}    Loading pending transfers...{c['r']}")
                transfers = await get_pending_transfers(wallet_obj, retries=num_retries)
                
                if not transfers:
                    print(f"{c['y']}    No pending transfers for this wallet.{c['r']}\n")
                    await results_queue.put(('skip', wallet_obj.name, 0))
                    return
                
                print(f"{c['g']}    Found {len(transfers)} claimable transfers for this wallet.{c['r']}")

                for j, transfer in enumerate(transfers):
                    transfer_id = transfer['id']
                    transfer_sender = transfer['sender'][:10]
                    print(f"{c['c']}    [{j+1}/{len(transfers)}] Claiming transfer #{transfer_id} from {transfer_sender}...{c['r']}", end='', flush=True)
                    
                    ok, result = await claim_private_transfer(transfer_id, wallet_obj, retries=num_retries)
                    
                    print(f"\r{' ' * (len(f'    [{j+1}/{len(transfers)}] Claiming transfer #{transfer_id} from {transfer_sender}...') + 3)}", end='', flush=True)

                    if ok:
                        wallet_success_count += 1
                        print(f"{c['g']}      ✓ Claimed {result.get('amount', 'unknown')}! (Tx Hash: {result.get('tx_hash', 'unknown')[:10]}...){c['r']}")
                        print(f"      {c['c']}Explorer: {OCTRASCAN_TX_URL}{result.get('tx_hash', 'unknown')}{c['r']}\n")
                        print(f"{c['g']}Your encrypted balance has been updated{c['r']}")
                        wallet_obj.last_update_time = 0
                    else:
                        wallet_fail_count += 1
                        error_msg = result.get('error', 'unknown error')
                        print(f"{c['R']}      ✗ Error claiming: {error_msg}{c['r']}\n")
                    await asyncio.sleep(0.1)
                
                print(f"\n{c['c']}    Wallet Claim Summary: {wallet_success_count} success, {wallet_fail_count} failed.{c['r']}\n")
                wallet_obj.last_update_time = 0
                await results_queue.put(('done', wallet_obj.name, wallet_success_count, wallet_fail_count))

            except Exception as wallet_e:
                print(f"{c['R']}  Wallet '{wallet_obj.name}' claim failed due to error: {wallet_e}{c['r']}\n")
                await results_queue.put(('fail_exception', wallet_obj.name, len(transfers)))

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_claim_concurrent(wallet_obj, results_queue, num_retries))

        await asyncio.gather(*tasks, return_exceptions=True)

        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                overall_success_wallets += counts[0]
                overall_failed_wallets += counts[1]
            elif result_type.startswith('fail_') or result_type == 'skip':
                overall_failed_wallets += (counts[0] if counts else 0)

        print(f"\n--- {c['B']}Overall Claim Summary (All Wallets){c['r']} ---")
        final_color = c['g'] if overall_failed_wallets == 0 else c['R']
        print(f"{final_color}{c['B']}Total Wallets: {overall_success_wallets} successful, {overall_failed_wallets} failed.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in claim_transfers_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def export_keys_all_wallets():
    try:
        cls()
        print(f"\n--- {c['B']}Export Keys (All Wallets){c['r']} ---\n")
        print(f"{c['R']}WARNING: This will export private keys for ALL loaded wallets to individual files!{c['r']}\n")

        confirm_input = await ainp(0, 0, f"{c['B']}{c['y']}Confirm exporting keys for EACH wallet? [y/n]: {c['r']}")
        confirm = confirm_input.strip().lower()
        if confirm != 'y':
            return

        print(f"\n--- {c['B']}Initiating Key Export for All Wallets (Concurrent)...{c['r']} ---\n")
        
        tasks = []
        results_queue = asyncio.Queue()

        async def _run_single_wallet_export_concurrent(wallet_obj, results_queue):
            wallet_export_count = 0
            try:
                print(f"\n{c['B']}  Starting Wallet: {wallet_obj.name} ({wallet_obj.addr[:8]}...){c['r']}")
                
                fn = f"octra_wallet_export_{wallet_obj.name}_{int(time.time())}.json"
                wallet_data = {
                    'priv': wallet_obj.priv,
                    'addr': wallet_obj.addr,
                    'rpc': wallet_obj.rpc,
                    'name': wallet_obj.name
                }
                os.umask(0o077)

                with open(fn, 'w') as f:
                    json.dump(wallet_data, f, indent=2)
                os.chmod(fn, 0o600)
                print(f"  {c['g']}Wallet saved to {fn}{c['r']}")
                print(f"  {c['R']}WARNING: File contains private key - keep safe!{c['r']}\n")
                wallet_export_count += 1
                await results_queue.put(('done', wallet_obj.name, wallet_export_count))

            except Exception as wallet_e:
                print(f"{c['R']}  Error saving wallet to file for {wallet_obj.name}: {wallet_e}{c['r']}\n")
                await results_queue.put(('fail_exception', wallet_obj.name, 0))

        for wallet_obj in wallets_available:
            tasks.append(_run_single_wallet_export_concurrent(wallet_obj, results_queue))
        
        await asyncio.gather(*tasks, return_exceptions=True)

        export_count_overall = 0
        failed_export_wallets = 0
        while not results_queue.empty():
            result_type, wallet_name, *counts = await results_queue.get()
            if result_type == 'done':
                export_count_overall += counts[0]
            elif result_type.startswith('fail_'):
                failed_export_wallets += 1

        print(f"\n--- {c['B']}Overall Export Summary (All Wallets){c['r']} ---")
        print(f"{c['g']}{c['B']}Total: {export_count_overall} wallets exported.{c['r']}")
        if failed_export_wallets > 0:
            print(f"{c['R']}  Some exports may have failed. Check messages above.{c['r']}")
        await awaitkey()
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred in export_keys_all_wallets: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()

async def ld_wallets():
    global wallets_available
    proxies_list = []
    wallets_available.clear()
    
    wallet_file = "wallet.json"

    if not os.path.exists(wallet_file):
        print(f"{c['R']}Error: '{wallet_file}' not found in the current directory.{c['r']}")
        print(f"{c['y']}Please create a 'wallet.json' file with your wallet(s) data.{c['r']}")
        return False
    
    try:
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, 'r') as pf:
                for line in pf:
                    proxy_entry = line.strip()
                    if proxy_entry and (proxy_entry.startswith('http://') or proxy_entry.startswith('https://')):
                        proxies_list.append(proxy_entry)
            if proxies_list:
                print(f"{c['g']}Loaded {len(proxies_list)} proxies from '{PROXY_FILE}'.{c['r']}")
            else:
                print(f"{c['y']}No valid proxies found in '{PROXY_FILE}'.{c['r']}")
        else:
            print(f"{c['y']}No '{PROXY_FILE}' found. Running without proxies.{c['r']}")

        with open(wallet_file, 'r') as f:
            data = json.load(f)
        
        load_ip_tasks = []
        temp_wallets = []

        if isinstance(data, list):
            for i, wallet_data in enumerate(data):
                priv_key = wallet_data.get('priv')
                addr_val = wallet_data.get('addr')
                rpc_url = wallet_data.get('rpc', 'http://localhost:8080')
                wallet_name = wallet_data.get('name', f"Wallet {i+1}")
                
                assigned_proxy = proxies_list[i] if i < len(proxies_list) else None

                if priv_key and addr_val:
                    wallet = Wallet(priv_key, addr_val, rpc_url, name=wallet_name, proxy=assigned_proxy)
                    temp_wallets.append(wallet)
                    if not rpc_url.startswith('https://') and 'localhost' not in rpc_url:
                        print(f"{c['y']}WARNING: Wallet '{wallet_name}' using insecure HTTP connection for RPC: {rpc_url}{c['r']}")
                    load_ip_tasks.append(wallet.get_proxy_ip())
                else:
                    print(f"{c['y']}Warning: Skipping invalid wallet entry in '{wallet_file}' (index {i}). Missing 'priv' or 'addr'.{c['r']}")
        elif isinstance(data, dict):
            priv_key = data.get('priv')
            addr_val = data.get('addr')
            rpc_url = data.get('rpc', 'http://localhost:8080')
            wallet_name = data.get('name', "Wallet 1")
            
            assigned_proxy = proxies_list[0] if proxies_list else None

            if priv_key and addr_val:
                wallet = Wallet(priv_key, addr_val, rpc_url, name=wallet_name, proxy=assigned_proxy)
                temp_wallets.append(wallet)
                if not rpc_url.startswith('https://') and 'localhost' not in rpc_url:
                    print(f"{c['y']}WARNING: Wallet '{wallet_name}' using insecure HTTP connection for RPC: {rpc_url}{c['r']}")
                load_ip_tasks.append(wallet.get_proxy_ip())
            else:
                print(f"{c['R']}Error: Single wallet in '{wallet_file}' is invalid. Missing 'priv' or 'addr'.{c['r']}")
        else:
            print(f"{c['R']}Error: Invalid JSON format in '{wallet_file}'. Expected a list of wallets or a single wallet object.{c['r']}")
            return False
        
        if load_ip_tasks:
            print(f"{c['c']}Fetching proxy IPs for wallets...{c['r']}")
            await asyncio.gather(*load_ip_tasks)

        for wallet in temp_wallets:
            wallets_available.append(wallet)
            print(f"{c['c']}Wallet '{wallet.name}' assigned proxy IP: {wallet.proxy_public_ip}{c['r']}")

    except json.JSONDecodeError as e:
        print(f"{c['R']}Error parsing '{wallet_file}': Invalid JSON format. {e}{c['r']}")
        return False
    except Exception as e:
        print(f"{c['R']}An unexpected error occurred while loading '{wallet_file}': {e}{c['r']}")
        return False
            
    return bool(wallets_available)

async def select_wallet():
    global current_selection, DAILY_MODE_ACTIVE, DAILY_MODE_TARGET_WALLET
    
    if DAILY_MODE_ACTIVE:
        print(f"{c['R']}Cannot change wallet selection while Daily Mode is active.{c['r']}")
        await awaitkey()
        return

    if not wallets_available:
        print(f"{c['y']}No wallets available to select.{c['r']}")
        await awaitkey()
        return

    while True:
        cls()
        
        print(f"\n--- {c['B']}Select Wallet{c['r']} ---")
        print(f"{c['c']}Choose which wallet you want to use:{c['r']}\n")
        
        for i, wallet in enumerate(wallets_available):
            print(f"{c['g']}[{i+1}]{c['r']} {c['B']}{wallet.name}{c['r']} ({wallet.addr[:10]}...)")
        
        print(f"\n{c['c']}--- Special ---{c['r']}")
        print(f"{c['y']}[all] Select ALL Wallets{c['r']}\n")
        
        choice_input = await ainp(0, 0, f"{c['B']}{c['y']}Enter choice (number or 'all'): {c['r']}")
        choice = choice_input.strip().lower()
        
        print("")

        if choice == 'all':
            current_selection = None
            print(f"{c['g']}Selected: ALL WALLETS{c['r']}")
            await awaitkey()
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(wallets_available):
                current_selection = wallets_available[idx]
                print(f"{c['g']}Selected: Wallet '{current_selection.name}'{c['r']}")
                await awaitkey()
                return
            else:
                print(f"{c['R']}Invalid number. Please try again.{c['r']}")
        except ValueError:
            print(f"{c['R']}Invalid input. Please enter a number or 'all'.{c['r']}")
        await awaitkey()

async def ensure_single_wallet_selected():
    global current_selection
    if current_selection is None:
        print(f"{c['R']}This command requires a single wallet to be selected.{c['r']}")
        print(f"{c['y']}Please use 's' command to select a specific wallet first.{c['r']}")
        await awaitkey()
        return False, None
    return True, current_selection

async def main():
    global current_selection, wallets_available, DAILY_MODE_ACTIVE, DAILY_RUNS_PER_WALLET_PER_DAY, DAILY_AMOUNT_PER_RECIPIENT, DAILY_MIN_DELAY, DAILY_MAX_DELAY, DAILY_RECIPIENT_LIMIT, DAILY_MODE_TARGET_WALLET, cancel_countdown_flag, DAILY_MODE_RETRIES
    
    sys_signal.signal(sys_signal.SIGINT, signal_handler)
    sys_signal.signal(sys_signal.SIGTERM, signal_handler)
    
    cls()
    print(f"{c['c']}Loading wallets...{c['r']}")
    
    if not await ld_wallets():
        print(f"{c['R']}No wallets loaded. Exiting.{c['r']}")
        await awaitkey()
        sys.exit(0)
    
    print("")

    if wallets_available:
        if len(wallets_available) == 1:
            current_selection = wallets_available[0]
            print(f"{c['g']}Auto-selected single wallet: '{current_selection.name}'{c['r']}")
            await asyncio.sleep(1)
        else:
            await select_wallet()
        
        if current_selection:
            print(f"{c['c']}Refreshing initial state for {current_selection.name}...{c['r']}")
            await st(current_selection)
            await gh(current_selection)
        else:
            print(f"{c['c']}Refreshing initial state for all wallets...{c['r']}")
            tasks = []
            for wallet in wallets_available:
                tasks.append(st(wallet))
                tasks.append(gh(wallet))
            await asyncio.gather(*tasks)
        await asyncio.sleep(0.5)
        
    try:
        while not stop_flag.is_set():
            if DAILY_MODE_ACTIVE:
                cls()
                print(f"\n{c['B']}--- Starting Daily Multi Send Run ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---{c['r']}")
                print(f"{c['y']}(Sit back & let the bot handle it 🧠, Use a VPS and run it inside a screen session, so you can go nap like a king while your script grinds 😴👑){c['r']}\n")
                
                recipients_file = "recipentaddress.txt"
                
                recipients_for_daily_run = await load_and_limit_recipients_from_file(file_path=recipients_file, prompt_limit=False)
                if recipients_for_daily_run is None:
                    print(f"{c['R']}Error loading/limiting recipients for daily run. Daily mode paused.{c['r']}")
                    DAILY_MODE_ACTIVE = False
                    DAILY_MODE_TARGET_WALLET = None
                    await asyncio.sleep(5)
                    continue
                if not recipients_for_daily_run:
                    print(f"{c['y']}No recipients selected for daily run. Daily mode paused.{c['r']}")
                    DAILY_MODE_ACTIVE = False
                    DAILY_MODE_TARGET_WALLET = None
                    await asyncio.sleep(5)
                    continue

                overall_daily_success_tx = 0
                overall_daily_failed_tx = 0
                
                if DAILY_MODE_TARGET_WALLET:
                    print(f"\n{c['B']}Running Daily Multi Send for selected wallet: {DAILY_MODE_TARGET_WALLET.name}{c['r']}")
                    success, failed = await _run_daily_multi_send_single_wallet(
                        DAILY_MODE_TARGET_WALLET, recipients_for_daily_run, DAILY_AMOUNT_PER_RECIPIENT,
                        DAILY_RUNS_PER_WALLET_PER_DAY, DAILY_MIN_DELAY, DAILY_MAX_DELAY, num_retries=DAILY_MODE_RETRIES
                    )
                    overall_daily_success_tx += success
                    overall_daily_failed_tx += failed
                else:
                    daily_run_tasks = []
                    daily_results_queue = asyncio.Queue()

                    for wallet_obj in wallets_available:
                        daily_run_tasks.append(_run_daily_multi_send_for_wallet(
                            wallet_obj, recipients_for_daily_run, DAILY_AMOUNT_PER_RECIPIENT,
                            DAILY_RUNS_PER_WALLET_PER_DAY, DAILY_MIN_DELAY, DAILY_MAX_DELAY,
                            daily_results_queue, num_retries=DAILY_MODE_RETRIES
                        ))
                    
                    await asyncio.gather(*daily_run_tasks, return_exceptions=True)

                    while not daily_results_queue.empty():
                        result_type, wallet_name, *counts = await daily_results_queue.get()
                        if result_type == 'done':
                            overall_daily_success_tx += counts[0]
                            overall_daily_failed_tx += counts[1]
                        elif result_type.startswith('fail_') or result_type == 'skip_no_recipients':
                            overall_daily_failed_tx += counts[0]

                print(f"\n{c['B']}--- Daily Multi Send Finished ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---{c['r']}")
                final_color = c['g'] if overall_daily_failed_tx == 0 else c['R']
                print(f"{final_color}{c['B']}Overall Daily Total Transactions: {overall_daily_success_tx} successful, {overall_daily_failed_tx} failed.{c['r']}")
                
                await countdown_timer(DAILY_INTERVAL_HOURS * 3600, message_prefix="Next run in")

                if stop_flag.is_set():
                    break
            
            else:
                await scr() 
                
                active_name = current_selection.name if current_selection else "ALL WALLETS"
                cmd = menu(active_name)

                if cmd == '1':
                    if current_selection is None:
                        await send_transaction_all_wallets()
                    else:
                        await tx_ui(current_selection)
                elif cmd == '2':
                    cls()
                    if current_selection is None:
                        print(f"{c['c']}Refreshing all wallets...{c['r']}")
                        tasks = []
                        for wallet in wallets_available:
                            wallet.last_update_time = 0
                            tasks.append(st(wallet))
                            tasks.append(gh(wallet))
                        await asyncio.gather(*tasks)
                        print(f"{c['g']}All wallets refreshed!{c['r']}")
                        await expl()
                    else:
                        print(f"{c['c']}Refreshing {current_selection.name}...{c['r']}")
                        current_selection.last_update_time = 0
                        await st(current_selection)
                        await gh(current_selection)
                        print(f"{c['g']}Wallet '{current_selection.name}' refreshed!{c['r']}")
                        await expl(current_selection)
                    await awaitkey()
                elif cmd == '3':
                    if current_selection is None:
                        await multi_send_all_wallets()
                    else:
                        await multi_ui(current_selection)
                elif cmd == '4':
                    if current_selection is None:
                        await encrypt_balance_all_wallets()
                    else:
                        await encrypt_balance_ui(current_selection)
                elif cmd == '5':
                    if current_selection is None:
                        await decrypt_balance_all_wallets()
                    else:
                        await decrypt_balance_ui(current_selection)
                elif cmd == '6':
                    if current_selection is None:
                        await private_transfer_all_wallets()
                    else:
                        await private_transfer_ui(current_selection)
                elif cmd == '7':
                    if current_selection is None:
                        await claim_transfers_all_wallets()
                    else:
                        await claim_transfers_ui(current_selection)
                elif cmd == '8':
                    if current_selection is None:
                        await export_keys_all_wallets()
                    else:
                        await exp_ui(current_selection)
                elif cmd == '9':
                    cls()
                    if current_selection is None:
                        print(f"{c['c']}Clearing history for all wallets...{c['r']}")
                        for wallet in wallets_available:
                            wallet.history.clear()
                            wallet.last_update_time = 0
                        print(f"{c['g']}All wallet histories cleared.{c['r']}")
                    else:
                        print(f"{c['c']}Clearing history for wallet '{current_selection.name}'...{c['r']}")
                        current_selection.history.clear()
                        current_selection.last_update_time = 0
                        print(f"{c['g']}History for wallet '{current_selection.name}' cleared.{c['r']}")
                    await awaitkey()
                elif cmd == 's':
                    if DAILY_MODE_ACTIVE:
                        print(f"{c['R']}Cannot change wallet selection while Daily Mode is active. Press Enter to return.{c['r']}")
                        await awaitkey()
                    else:
                        await select_wallet()
                elif cmd in ['0', 'q', '']:
                    break
                else:
                    print(f"\n{c['R']}Invalid command. Please try again.{c['r']}")
                    await awaitkey()
    
    except Exception as e:
        print(f"\n{c['R']}An unexpected error occurred during execution: {e}{c['r']}")
        traceback.print_exc()
        await awaitkey()
    finally:
        await close_all_sessions()
        executor.shutdown(wait=False)
        cls()
        print(f"{c['r']}Application terminated.{c['r']}")
        sys_signal.sys.exit(0)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)
    
    try:
        asyncio.run(main())
    except sys_signal.KeyboardInterrupt:
        print(f"\n{c['y']}Exiting gracefully...{c['r']}")
    except Exception as e:
        print(f"\n{c['R']}An error occurred before or after main loop execution: {e}{c['r']}")
        traceback.print_exc()
    finally:
        pass
