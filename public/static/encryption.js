/**
 * ThinkEncryption 混合加密客户端
 * 
 * 使用方法:
 * const client = new HybridEncryptionClient('http://localhost:8000');
 * await client.init();
 * await client.exchangeKeys();
 * const result = await client.request('/api/test', { message: 'hello' });
 */
class HybridEncryptionClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
        this.clientId = this.getOrCreateClientId();
        this.aesKey = null;
        this.iv = null;
        this.rsaVersion = null;
        this.publicKey = null;
        this.versionInfo = null;
    }

    /**
     * 获取或创建客户端ID
     */
    getOrCreateClientId() {
        let clientId = localStorage.getItem('hybrid_enc_client_id');
        if (!clientId) {
            clientId = this.generateUUID();
            localStorage.setItem('hybrid_enc_client_id', clientId);
        }
        return clientId;
    }

    /**
     * 生成UUID
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    /**
     * 生成随机字节
     */
    generateRandomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }

    /**
     * ArrayBuffer 转 Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Base64 转 ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * 导入RSA公钥
     */
    async importPublicKey(pem) {
        const pemHeader = '-----BEGIN PUBLIC KEY-----';
        const pemFooter = '-----END PUBLIC KEY-----';
        const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
        const binaryDer = this.base64ToArrayBuffer(pemContents);

        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );
    }

    /**
     * RSA-OAEP 加密 (分块)
     */
    async rsaEncrypt(data, publicKey) {
        const keyBits = this.versionInfo?.key_bits || 3072;
        // OAEP with SHA-256: max = (keyBits/8) - 2*32 - 2 = keyBits/8 - 66
        const maxChunk = Math.floor(keyBits / 8) - 66;
        
        const dataBytes = new TextEncoder().encode(data);
        let encrypted = '';
        
        // 分块加密
        for (let i = 0; i < dataBytes.length; i += maxChunk) {
            const chunk = dataBytes.slice(i, i + maxChunk);
            const chunkEncrypted = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                chunk
            );
            encrypted += this.arrayBufferToBase64(chunkEncrypted);
        }
        
        return encrypted;
    }

    /**
     * AES-CBC 加密 + HMAC
     * 格式: base64(iv + cipher + hmac)
     */
    async aesEncrypt(data, key, iv) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        );

        const encoded = new TextEncoder().encode(JSON.stringify(data));
        
        // 填充到16字节倍数
        const padded = this.pkcs7Pad(encoded);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            padded
        );

        // 计算 HMAC (iv + cipher)
        const cipherWithIv = new Uint8Array(iv.length + encrypted.byteLength);
        cipherWithIv.set(iv, 0);
        cipherWithIv.set(new Uint8Array(encrypted), iv.length);
        
        const hmac = await this.computeHmac(cipherWithIv, key);
        
        // 组装: iv + cipher + hmac
        const result = new Uint8Array(iv.length + encrypted.byteLength + hmac.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), iv.length);
        result.set(new Uint8Array(hmac), iv.length + encrypted.byteLength);
        
        return this.arrayBufferToBase64(result.buffer);
    }

    /**
     * AES-CBC 解密 + HMAC 验证
     */
    async aesDecrypt(encryptedData, key) {
        const data = new Uint8Array(this.base64ToArrayBuffer(encryptedData));
        const ivLength = 16;
        const hmacLength = 32;
        
        if (data.length < ivLength + hmacLength) {
            throw new Error('加密数据格式错误');
        }
        
        const iv = data.slice(0, ivLength);
        const hmac = data.slice(data.length - hmacLength);
        const cipherWithIv = data.slice(0, data.length - hmacLength);
        
        // 验证 HMAC
        const computedHmac = await this.computeHmac(cipherWithIv, key);
        if (!this.constantTimeCompare(hmac, new Uint8Array(computedHmac))) {
            throw new Error('HMAC 验证失败，数据可能被篡改');
        }
        
        const cipher = data.slice(ivLength, data.length - hmacLength);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            cipher
        );

        const unpadded = this.pkcs7Unpad(new Uint8Array(decrypted));
        return JSON.parse(new TextDecoder().decode(unpadded));
    }

    /**
     * 计算 HMAC-SHA256
     */
    async computeHmac(data, key) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        return await crypto.subtle.sign('HMAC', cryptoKey, data);
    }

    /**
     * PKCS7 填充
     */
    pkcs7Pad(data, blockSize = 16) {
        const padLength = blockSize - (data.length % blockSize);
        const padded = new Uint8Array(data.length + padLength);
        padded.set(data);
        padded.fill(padLength, data.length);
        return padded;
    }

    /**
     * PKCS7 填充移除
     */
    pkcs7Unpad(data) {
        const padLength = data[data.length - 1];
        if (padLength < 1 || padLength > 16 || padLength > data.length) {
            return data;
        }
        return data.slice(0, data.length - padLength);
    }

    /**
     * 常数时间比较 (防止时序攻击)
     */
    constantTimeCompare(a, b) {
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }

    /**
     * 初始化客户端
     */
    async init() {
        // 尝试加载已存储的密钥
        if (this.loadStoredKeys()) {
            return { cached: true };
        }
        return { cached: false };
    }

    /**
     * 获取服务端公钥
     */
    async fetchPublicKey() {
        const response = await fetch(`${this.baseUrl}/api/encryption/public-key`);
        const result = await response.json();

        if (result.code !== 200) {
            throw new Error(result.message);
        }

        this.versionInfo = {
            version: result.data.version,
            key_bits: result.data.key_bits,
            previous_version: result.data.previous_version,
            transition_end_at: result.data.transition_end_at,
        };
        this.rsaVersion = result.data.version;
        this.publicKey = await this.importPublicKey(result.data.public_key);

        return result.data;
    }

    /**
     * 密钥交换
     */
    async exchangeKeys() {
        // 获取公钥
        if (!this.publicKey) {
            await this.fetchPublicKey();
        }

        // 生成 AES 密钥和 IV
        this.aesKey = this.generateRandomBytes(32);
        this.iv = this.generateRandomBytes(16);

        // RSA 加密 AES 密钥和 IV (转字符串)
        const aesKeyStr = String.fromCharCode(...this.aesKey);
        const ivStr = String.fromCharCode(...this.iv);
        
        const encryptedAesKey = await this.rsaEncrypt(aesKeyStr, this.publicKey);
        const encryptedIv = await this.rsaEncrypt(ivStr, this.publicKey);

        // 发送给后端
        const response = await fetch(`${this.baseUrl}/api/encryption/exchange-keys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Client-ID': this.clientId,
            },
            body: JSON.stringify({
                encrypted_aes_key: encryptedAesKey,
                encrypted_iv: encryptedIv,
                rsa_version: this.rsaVersion,
            }),
        });

        const result = await response.json();

        if (result.code !== 200) {
            throw new Error(result.message);
        }

        // 保存到本地存储
        this.saveKeys();

        return result.data;
    }

    /**
     * 保存密钥到本地存储
     */
    saveKeys() {
        localStorage.setItem('hybrid_enc_aes_key', this.arrayBufferToBase64(this.aesKey));
        localStorage.setItem('hybrid_enc_iv', this.arrayBufferToBase64(this.iv));
        localStorage.setItem('hybrid_enc_rsa_version', this.rsaVersion);
        if (this.versionInfo) {
            localStorage.setItem('hybrid_enc_version_info', JSON.stringify(this.versionInfo));
        }
    }

    /**
     * 加载本地存储的密钥
     */
    loadStoredKeys() {
        const aesKeyBase64 = localStorage.getItem('hybrid_enc_aes_key');
        const ivBase64 = localStorage.getItem('hybrid_enc_iv');
        const rsaVersion = localStorage.getItem('hybrid_enc_rsa_version');
        const versionInfoStr = localStorage.getItem('hybrid_enc_version_info');

        if (aesKeyBase64 && ivBase64 && rsaVersion) {
            this.aesKey = new Uint8Array(this.base64ToArrayBuffer(aesKeyBase64));
            this.iv = new Uint8Array(this.base64ToArrayBuffer(ivBase64));
            this.rsaVersion = rsaVersion;
            if (versionInfoStr) {
                try {
                    this.versionInfo = JSON.parse(versionInfoStr);
                } catch (e) {}
            }
            return true;
        }
        return false;
    }

    /**
     * 发送加密请求
     * @param {string} url - 请求路径
     * @param {object} options - fetch 选项
     */
    async request(url, options = {}) {
        // 确保有密钥
        if (!this.aesKey || !this.iv) {
            const hasStoredKeys = this.loadStoredKeys();
            if (!hasStoredKeys) {
                await this.exchangeKeys();
            }
        }

        const headers = {
            'X-Client-ID': this.clientId,
            ...options.headers,
        };

        // 加密请求数据
        if (options.body) {
            const encryptedBody = await this.aesEncrypt(options.body, this.aesKey, this.iv);
            options.body = JSON.stringify({ encrypted_data: encryptedBody });
            headers['Content-Type'] = 'application/json';
        }

        const response = await fetch(`${this.baseUrl}${url}`, {
            ...options,
            headers,
        });

        // 处理密钥需要更新
        if (response.status === 426 || response.status === 449) {
            await this.exchangeKeys();
            return this.request(url, options);
        }

        // 检查是否需要更新密钥 (异步，不阻塞)
        const needUpdate = response.headers.get('X-Key-Update-Required');
        if (needUpdate === 'true') {
            this.exchangeKeys().catch(console.error);
        }

        const result = await response.json();

        // 解密响应数据
        if (result.data && result.data.encrypted_data) {
            result.data = await this.aesDecrypt(
                result.data.encrypted_data,
                this.aesKey
            );
        }

        return result;
    }

    /**
     * 获取加密状态
     */
    async getStatus() {
        const response = await fetch(`${this.baseUrl}/api/encryption/status`, {
            headers: {
                'X-Client-ID': this.clientId,
            },
        });
        return await response.json();
    }

    /**
     * 清除本地密钥
     */
    clearKeys() {
        localStorage.removeItem('hybrid_enc_client_id');
        localStorage.removeItem('hybrid_enc_aes_key');
        localStorage.removeItem('hybrid_enc_iv');
        localStorage.removeItem('hybrid_enc_rsa_version');
        localStorage.removeItem('hybrid_enc_version_info');
        this.aesKey = null;
        this.iv = null;
        this.rsaVersion = null;
        this.publicKey = null;
        this.versionInfo = null;
    }

    /**
     * 获取客户端信息
     */
    getInfo() {
        return {
            clientId: this.clientId,
            hasKeys: !!(this.aesKey && this.iv),
            rsaVersion: this.rsaVersion,
            versionInfo: this.versionInfo,
        };
    }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HybridEncryptionClient;
}
