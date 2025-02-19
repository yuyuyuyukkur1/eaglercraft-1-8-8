class CryptoExtension {
    getInfo() {
      return {
        id: 'cryptoExtension', // 拡張機能の一意なID
        name: 'Crypto', // 拡張機能の表示名
        blocks: [
          {
            opcode: 'calculateHash', // ハッシュ計算関数
            blockType: Scratch.BlockType.REPORTER,
            text: '[ALGORITHM] hash of [TEXT]', // ブロックの表示テキスト
            arguments: {
              ALGORITHM: {
                type: Scratch.ArgumentType.STRING,
                menu: 'algorithms',
                defaultValue: 'SHA-256'
              },
              TEXT: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'Hello, world!'
              }
            }
          },
          {
            opcode: 'encryptText', // 暗号化関数
            blockType: Scratch.BlockType.REPORTER,
            text: 'encrypt [TEXT] with password [PASSWORD]',
            arguments: {
              TEXT: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'Secret message'
              },
              PASSWORD: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'password123'
              }
            }
          },
          {
            opcode: 'decryptText', // 復号関数
            blockType: Scratch.BlockType.REPORTER,
            text: 'decrypt [TEXT] with password [PASSWORD]',
            arguments: {
              TEXT: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'Encrypted data'
              },
              PASSWORD: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'password123'
              }
            }
          }
        ],
        menus: {
          algorithms: {
            acceptReporters: true,
            items: ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'MD5']
          }
        }
      };
    }
  
    calculateHash(args) {
      const text = args.TEXT;
      const algorithm = args.ALGORITHM.toUpperCase();
  
      if (['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].includes(algorithm)) {
        return this.calculateSHA(text, algorithm);
      } else if (algorithm === 'MD5') {
        return this.calculateMD5(text);
      } else {
        return 'Unsupported algorithm';
      }
    }
  
    calculateSHA(message, algorithm) {
      const msgBuffer = new TextEncoder().encode(message);
  
      return crypto.subtle.digest(algorithm, msgBuffer).then(hashBuffer => {
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        return hashHex;
      });
    }
  
    calculateMD5(message) {
      return new Promise((resolve) => {
        if (typeof this.md5 !== 'function') {
          const script = document.createElement('script');
          script.src =
            'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
          script.onload = () => {
            this.md5 = function (msg) {
              return CryptoJS.MD5(msg).toString();
            };
            resolve(this.md5(message));
          };
          script.onerror = () => {
            resolve('Failed to load MD5 library');
          };
          document.head.appendChild(script);
        } else {
          resolve(this.md5(message));
        }
      });
    }
  
    encryptText(args) {
      const text = args.TEXT;
      const password = args.PASSWORD;
      return this.encryptAES(text, password);
    }
  
    decryptText(args) {
      const text = args.TEXT;
      const password = args.PASSWORD;
      return this.decryptAES(text, password);
    }
  
    async encryptAES(plainText, password) {
      try {
        const pwUtf8 = new TextEncoder().encode(password);
        const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const alg = { name: 'AES-GCM', iv: iv };
        const key = await crypto.subtle.importKey(
          'raw',
          pwHash,
          alg,
          false,
          ['encrypt']
        );
  
        const ptUint8 = new TextEncoder().encode(plainText);
        const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8);
  
        const ctArray = Array.from(new Uint8Array(ctBuffer));
        const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('');
        const ivStr = Array.from(iv)
          .map(byte => String.fromCharCode(byte))
          .join('');
        const ctBase64 = btoa(ivStr + ctStr);
  
        return ctBase64;
      } catch (e) {
        return 'Encryption failed';
      }
    }
  
    async decryptAES(cipherText, password) {
      try {
        const pwUtf8 = new TextEncoder().encode(password);
        const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  
        const ctStr = atob(cipherText);
        const iv = new Uint8Array(
          Array.from(ctStr.slice(0, 12)).map(ch => ch.charCodeAt(0))
        );
        const ctUint8 = new Uint8Array(
          Array.from(ctStr.slice(12)).map(ch => ch.charCodeAt(0))
        );
  
        const alg = { name: 'AES-GCM', iv: iv };
        const key = await crypto.subtle.importKey(
          'raw',
          pwHash,
          alg,
          false,
          ['decrypt']
        );
  
        const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8);
        const plainText = new TextDecoder().decode(plainBuffer);
  
        return plainText;
      } catch (e) {
        return 'Decryption failed';
      }
    }
  }
  
  Scratch.extensions.register(new CryptoExtension());
  
