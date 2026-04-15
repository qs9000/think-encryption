/**
 * 混合加密客户端工具类
 * 用于前后端分离项目的加密通信
 */
class HybridEncryptionClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
        this.clientId = this.getOrCreateClientId();
        this.aesKey = null;
        this.iv = null;
        this.rsaVersion = null;
        this.publicKey = null;
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
     * 将ArrayBuffer转为Base64
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
     * 将Base64转为ArrayBuffer
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
     * RSA加密
     */
    async rsaEncrypt(data, publicKey) {
        const encoded = new TextEncoder().encode(data);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            encoded
        );
        return this.arrayBufferToBase64(encrypted);
    }

    /**
     * AES加密
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
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            encoded
        );

        // IV + 密文
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), iv.length);
        return this.arrayBufferToBase64(result.buffer);
    }

    /**
     * AES解密
     */
    async aesDecrypt(encryptedData, key, iv) {
        const data = this.base64ToArrayBuffer(encryptedData);
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
            data.slice(16) // 跳过IV
        );

        const decoded = new TextDecoder().decode(decrypted);
        return JSON.parse(decoded);
    }

    /**
     * 获取RSA公钥
     */
    async fetchPublicKey() {
        const response = await fetch(`${this.baseUrl}/api/encryption/public-key`);
        const result = await response.json();

        if (result.code !== 200) {
            throw new Error(result.message);
        }

        this.publicKey = await this.importPublicKey(result.data.public_key);
        this.rsaVersion = result.data.version;

        return result.data;
    }

    /**
     * 交换密钥
     */
    async exchangeKeys() {
        // 获取公钥
        if (!this.publicKey) {
            await this.fetchPublicKey();
        }

        // 生成AES密钥和IV
        this.aesKey = this.generateRandomBytes(32);
        this.iv = this.generateRandomBytes(16);

        // RSA加密AES密钥和IV
        const encryptedAesKey = await this.rsaEncrypt(
            String.fromCharCode(...this.aesKey),
            this.publicKey
        );
        const encryptedIv = await this.rsaEncrypt(
            String.fromCharCode(...this.iv),
            this.publicKey
        );

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
        localStorage.setItem('hybrid_enc_aes_key', this.arrayBufferToBase64(this.aesKey));
        localStorage.setItem('hybrid_enc_iv', this.arrayBufferToBase64(this.iv));
        localStorage.setItem('hybrid_enc_rsa_version', this.rsaVersion);

        return result.data;
    }

    /**
     * 加载本地存储的密钥
     */
    loadStoredKeys() {
        const aesKeyBase64 = localStorage.getItem('hybrid_enc_aes_key');
        const ivBase64 = localStorage.getItem('hybrid_enc_iv');
        const rsaVersion = localStorage.getItem('hybrid_enc_rsa_version');

        if (aesKeyBase64 && ivBase64 && rsaVersion) {
            this.aesKey = new Uint8Array(this.base64ToArrayBuffer(aesKeyBase64));
            this.iv = new Uint8Array(this.base64ToArrayBuffer(ivBase64));
            this.rsaVersion = rsaVersion;
            return true;
        }

        return false;
    }

    /**
     * 发送加密请求
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

        // 检查是否需要重新交换密钥
        if (response.status === 426) {
            await this.exchangeKeys();
            return this.request(url, options);
        }

        if (response.status === 449) {
            await this.exchangeKeys();
            return this.request(url, options);
        }

        // 检查是否需要更新密钥
        const needUpdate = response.headers.get('X-Key-Update-Required');
        if (needUpdate === 'true') {
            // 异步更新密钥，不阻塞当前请求
            this.exchangeKeys().catch(console.error);
        }

        const result = await response.json();

        // 解密响应数据
        if (result.data && result.data.encrypted_data) {
            result.data = await this.aesDecrypt(
                result.data.encrypted_data,
                this.aesKey,
                this.iv
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
        this.aesKey = null;
        this.iv = null;
        this.rsaVersion = null;
        this.publicKey = null;
    }
}

// 导出
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HybridEncryptionClient;
}
